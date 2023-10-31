package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bvinc/go-sqlite-lite/sqlite3"
	"github.com/pkg/profile"
	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/machinebox/progress"
	"github.com/sirupsen/logrus"

	// "github.com/pkg/profile"

	"github.com/perforce/p4prometheus/version"
	p4dlog "github.com/RishiMunagala/go-libp4dlog"
	"github.com/RishiMunagala/go-libp4dlog/metrics"
)

const statementsPerTransaction = 50 * 1000

// We use SQL comments which appear if you use ".schema" within Sqlite3 - helpful reminder
func writeHeader(f io.Writer) {
	fmt.Fprintf(f, `CREATE TABLE IF NOT EXISTS process -- main process table for commands
	(processkey CHAR(50) NOT NULL, -- prime key (hash of line), used to join with tableUse
	lineNumber INT NOT NULL, -- Line no for first occurrence of pid for this command
	pid INT NOT NULL, -- Process ID
	startTime DATETIME NOT NULL, endTime DATETIME NULL, -- Start/end time of command
	computedLapse FLOAT NULL, completedLapse FLOAT NULL, -- Lapse time for compute phase and total command (secs)
	user TEXT NOT NULL, workspace TEXT NOT NULL, ip TEXT NOT NULL, -- user/workspace name/IP
	app TEXT NOT NULL, -- p4api application reported, e.g. p4/p4v etc
	cmd TEXT NOT NULL, -- command executed, e.g. user-sync
	args TEXT NULL, -- command args - may be truncated
	uCpu INT NULL, sCpu INT NULL, -- user and system CPU (milliseconds)
	diskIn INT NULL, diskOut INT NULL, -- no of 512b disk write/read
	ipcIn INT NULL, ipcOut INT NULL,  -- IPC msgs received/sent
	maxRss INT NULL, -- KB of physical memory that processes used simultaneously
	pageFaults INT NULL, -- number of page faults that were serviced by doing I/O
	memMB INT NULL, memPeakMB INT NULL, -- Memory per command and max memory (for commands on same pid) - in MB
	rpcMsgsIn INT NULL, rpcMsgsOut INT NULL, -- Count of RPC messages rcvd/sent
	rpcSizeIn INT NULL, rpcSizeOut INT NULL, -- Total size of RPC messages rcvd/sent
	rpcHimarkFwd INT NULL, rpcHimarkRev INT NULL, -- Snd/Rcv Window size for OS
	rpcSnd FLOAT NULL, rpcRcv FLOAT NULL, -- times (secs) spent waiting to send RPC requests and waiting to receive RPC responses
	running INT NULL, -- No of concurrent running commands
	netSyncFilesAdded INT NULL, netSyncFilesUpdated INT NULL, netSyncFilesDeleted INT NULL, -- estimated counts
	netSyncBytesAdded INT NULL, netSyncBytesUpdated INT NULL, -- estimated byte counts
	-- Following are for accessing librarian (lbr) files of different types (RCS/Binary/Compressed/Uncompressed)
	lbrRcsOpens INT NULL, lbrRcsCloses INT NULL, lbrRcsCheckins INT NULL, lbrRcsExists INT NULL,
	lbrRcsReads INT NULL, lbrRcsReadBytes INT NULL, lbrRcsWrites INT NULL, lbrRcsWriteBytes INT NULL,
	lbrRcsDigests INT NULL, lbrRcsFileSizes INT NULL, lbrRcsModtimes INT NULL, lbrRcsCopies INT NULL,
	lbrBinaryOpens INT NULL, lbrBinaryCloses INT NULL, lbrBinaryCheckins INT NULL, lbrBinaryExists INT NULL,
	lbrBinaryReads INT NULL, lbrBinaryReadBytes INT NULL, lbrBinaryWrites INT NULL, lbrBinaryWriteBytes INT NULL,
	lbrBinaryDigests INT NULL, lbrBinaryFileSizes INT NULL, lbrBinaryModtimes INT NULL, lbrBinaryCopies INT NULL,
	lbrCompressOpens INT NULL, lbrCompressCloses INT NULL, lbrCompressCheckins INT NULL, lbrCompressExists INT NULL,
	lbrCompressReads INT NULL, lbrCompressReadBytes INT NULL, lbrCompressWrites INT NULL, lbrCompressWriteBytes INT NULL,
	lbrCompressDigests INT NULL, lbrCompressFileSizes INT NULL, lbrCompressModtimes INT NULL, lbrCompressCopies INT NULL,
	lbrUncompressOpens INT NULL, lbrUncompressCloses INT NULL, lbrUncompressCheckins INT NULL, lbrUncompressExists INT NULL,
	lbrUncompressReads INT NULL, lbrUncompressReadBytes INT NULL, lbrUncompressWrites INT NULL, lbrUncompressWriteBytes INT NULL,
	lbrUncompressDigests INT NULL, lbrUncompressFileSizes INT NULL, lbrUncompressModtimes INT NULL, lbrUncompressCopies INT NULL,
	error TEXT NULL, -- any error text for command
	PRIMARY KEY (processkey, lineNumber));
`)
	fmt.Fprintf(f, `CREATE TABLE IF NOT EXISTS tableUse
	(processkey CHAR(50) NOT NULL, lineNumber INT NOT NULL, -- primary key
	tableName VARCHAR(255) NOT NULL, -- name of table (or trigger)
	pagesIn INT NULL, pagesOut INT NULL, pagesCached INT NULL,
	pagesSplitInternal INT NULL, pagesSplitLeaf INT NULL, -- B-tree split counts
	readLocks INT NULL, writeLocks INT NULL, -- Count of read/write locks
	getRows INT NULL, posRows INT NULL, scanRows INT NULL, -- Count of get/position/scan for rows
	putRows int NULL, delRows INT NULL,  -- Count of put/delete for rows
	totalReadWait INT NULL, totalReadHeld INT NULL, -- Totals (milliseconds)
	totalWriteWait INT NULL, totalWriteHeld INT NULL, -- Totals (milliseconds)
	maxReadWait INT NULL, maxReadHeld INT NULL, -- Max (milliseconds)
	maxWriteWait INT NULL, maxWriteHeld INT NULL, -- Max (milliseconds)
	peekCount INT NULL, -- Count of peeks
	totalPeekWait INT NULL, totalPeekHeld INT NULL, -- Totals (milliseconds)
	maxPeekWait INT NULL, maxPeekHeld INT NULL, -- Totals (milliseconds)
	triggerLapse FLOAT NULL, -- lapse time (seconds) for triggers - tableName=trigger name
	PRIMARY KEY (processkey, lineNumber, tableName));
`)
	// Trade security for speed - easy to re-run if a problem (hopefully!)
	fmt.Fprintf(f, "PRAGMA journal_mode = OFF;\nPRAGMA synchronous = OFF;\n")
}

func startTransaction(f io.Writer) {
	fmt.Fprintf(f, "BEGIN TRANSACTION;\n")
}

func writeTransaction(f io.Writer) {
	fmt.Fprintf(f, "COMMIT;\nBEGIN TRANSACTION;\n")
}

func writeTrailer(f io.Writer) {
	fmt.Fprintf(f, "COMMIT;\n")
}

func dateStr(t time.Time) string {
	var blankTime time.Time
	if t == blankTime {
		return ""
	}
	return t.Format("2006/01/02 15:04:05")
}

func getProcessStatement() string {
	return `INSERT INTO process
		(processkey, lineNumber, pid,
		startTime ,endTime, computedLapse, completedLapse,
		user, workspace, ip, app, cmd,
		args, uCpu, sCpu, diskIn, diskOut, ipcIn,
		ipcOut, maxRss, pageFaults, memMB, memPeakMB, rpcMsgsIn, rpcMsgsOut,
		rpcSizeIn, rpcSizeOut, rpcHimarkFwd, rpcHimarkRev,
		rpcSnd, rpcRcv, running,
		netSyncFilesAdded, netSyncFilesUpdated, netSyncFilesDeleted,
		netSyncBytesAdded, netSyncBytesUpdated,
		lbrRcsOpens, lbrRcsCloses, lbrRcsCheckins, lbrRcsExists,
		lbrRcsReads, lbrRcsReadBytes, lbrRcsWrites, lbrRcsWriteBytes,
		lbrRcsDigests, lbrRcsFileSizes, lbrRcsModtimes, lbrRcsCopies,
		lbrBinaryOpens, lbrBinaryCloses, lbrBinaryCheckins, lbrBinaryExists,
		lbrBinaryReads, lbrBinaryReadBytes, lbrBinaryWrites, lbrBinaryWriteBytes,
		lbrBinaryDigests, lbrBinaryFileSizes, lbrBinaryModtimes, lbrBinaryCopies,
		lbrCompressOpens, lbrCompressCloses, lbrCompressCheckins,
		lbrCompressExists, lbrCompressReads, lbrCompressReadBytes,
		lbrCompressWrites, lbrCompressWriteBytes,
        lbrCompressDigests, lbrCompressFileSizes, lbrCompressModtimes, lbrCompressCopies,
		lbrUncompressOpens, lbrUncompressCloses, lbrUncompressCheckins,
		lbrUncompressExists, lbrUncompressReads, lbrUncompressReadBytes,
		lbrUncompressWrites, lbrUncompressWriteBytes,
		lbrUncompressDigests, lbrUncompressFileSizes, lbrUncompressModtimes, lbrUncompressCopies,
		error)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
}

func getTableUseStatement() string {
	return `INSERT INTO tableuse
		(processkey, lineNumber, tableName, pagesIn, pagesOut, pagesCached,
		pagesSplitInternal, pagesSplitLeaf,
		readLocks, writeLocks, getRows, posRows, scanRows,
		putRows, delRows, totalReadWait, totalReadHeld,
		totalWriteWait, totalWriteHeld, maxReadWait, maxReadHeld,
		maxWriteWait, maxWriteHeld, peekCount,
		totalPeekWait, totalPeekHeld, maxPeekWait, maxPeekHeld,
		triggerLapse)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
}

func preparedInsert(logger *logrus.Logger, stmtProcess, stmtTableuse *sqlite3.Stmt, cmd *p4dlog.Command) int64 {
	rows := 1
	err := stmtProcess.Exec(
		cmd.GetKey(), cmd.LineNo, cmd.Pid, dateStr(cmd.StartTime), dateStr(cmd.EndTime),
		float64(cmd.ComputeLapse), float64(cmd.CompletedLapse),
		string(cmd.User), string(cmd.Workspace), string(cmd.IP), string(cmd.App), string(cmd.Cmd), string(cmd.Args),
		cmd.UCpu, cmd.SCpu, cmd.DiskIn, cmd.DiskOut,
		cmd.IpcIn, cmd.IpcOut, cmd.MaxRss, cmd.PageFaults, cmd.MemMB, cmd.MemPeakMB, cmd.RPCMsgsIn, cmd.RPCMsgsOut,
		cmd.RPCSizeIn, cmd.RPCSizeOut, cmd.RPCHimarkFwd, cmd.RPCHimarkRev,
		float64(cmd.RPCSnd), float64(cmd.RPCRcv), cmd.Running,
		cmd.NetFilesAdded, cmd.NetFilesUpdated, cmd.NetFilesDeleted,
		cmd.NetBytesAdded, cmd.NetBytesUpdated,
		cmd.LbrRcsOpens, cmd.LbrRcsCloses, cmd.LbrRcsCheckins, cmd.LbrRcsExists,
		cmd.LbrRcsReads, cmd.LbrRcsReadBytes, cmd.LbrRcsWrites, cmd.LbrRcsWriteBytes,
		cmd.LbrRcsDigests, cmd.LbrRcsFileSizes, cmd.LbrRcsModTimes, cmd.LbrRcsCopies,
		cmd.LbrBinaryOpens, cmd.LbrBinaryCloses, cmd.LbrBinaryCheckins, cmd.LbrBinaryExists,
		cmd.LbrBinaryReads, cmd.LbrBinaryReadBytes, cmd.LbrBinaryWrites, cmd.LbrBinaryWriteBytes,
		cmd.LbrBinaryDigests, cmd.LbrBinaryFileSizes, cmd.LbrBinaryModTimes, cmd.LbrBinaryCopies,
		cmd.LbrCompressOpens, cmd.LbrCompressCloses, cmd.LbrCompressCheckins, cmd.LbrCompressExists,
		cmd.LbrCompressReads, cmd.LbrCompressReadBytes, cmd.LbrCompressWrites, cmd.LbrCompressWriteBytes,
		cmd.LbrCompressDigests, cmd.LbrCompressFileSizes, cmd.LbrCompressModTimes, cmd.LbrCompressCopies,
		cmd.LbrUncompressOpens, cmd.LbrUncompressCloses, cmd.LbrUncompressCheckins, cmd.LbrUncompressExists,
		cmd.LbrUncompressReads, cmd.LbrUncompressReadBytes, cmd.LbrUncompressWrites, cmd.LbrUncompressWriteBytes,
		cmd.LbrUncompressDigests, cmd.LbrUncompressFileSizes, cmd.LbrUncompressModTimes, cmd.LbrUncompressCopies,
		cmd.CmdError)
	if err != nil {
		logger.Errorf("Process insert: %v pid %d, lineNo %d, %s",
			err, cmd.Pid, cmd.LineNo, string(cmd.Cmd))
	}
	for _, t := range cmd.Tables {
		rows++
		err := stmtTableuse.Exec(
			cmd.GetKey(), cmd.LineNo, t.TableName, t.PagesIn, t.PagesOut, t.PagesCached,
			t.PagesSplitInternal, t.PagesSplitLeaf,
			t.ReadLocks, t.WriteLocks, t.GetRows, t.PosRows, t.ScanRows, t.PutRows, t.DelRows,
			t.TotalReadWait, t.TotalReadHeld, t.TotalWriteWait, t.TotalWriteHeld,
			t.MaxReadWait, t.MaxReadHeld, t.MaxWriteWait, t.MaxWriteHeld, t.PeekCount,
			t.TotalPeekWait, t.TotalPeekHeld, t.MaxPeekWait, t.MaxPeekHeld, float64(t.TriggerLapse))
		if err != nil {
			logger.Errorf("Tableuse insert: %v pid %d, lineNo %d, %s, %s, %s",
				err, cmd.Pid, cmd.LineNo, cmd.GetKey(), string(cmd.Cmd), string(cmd.Args))
		}
	}
	return int64(rows)
}

func writeSQL(f io.Writer, cmd *p4dlog.Command) int64 {
	rows := 1
	fmt.Fprintf(f, `INSERT INTO process VALUES ("%s",%d,%d,"%s","%s",%0.3f,%0.3f,`+
		`"%s","%s","%s","%s","%s","%s",%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,`+
		`%.3f,%.3f,%d,%d,%d,%d,%d,%d,`+
		`%d,%d,%d,%d,%d,%d,%d,%d,`+
		`%d,%d,%d,%d,%d,%d,%d,%d,`+
		`%d,%d,%d,%d,%d,%d,%d,%d,`+
		`%d,%d,%d,%d,%d,%d,%d,%d,`+
		`%d,%d,%d,%d,`+
		`%d,%d,%d,%d,%d,%d,%d,%d,`+
		`%d,%d,%d,%d,"%v");`+"\n",
		cmd.GetKey(), cmd.LineNo, cmd.Pid, dateStr(cmd.StartTime), dateStr(cmd.EndTime),
		cmd.ComputeLapse, cmd.CompletedLapse,
		cmd.User, cmd.Workspace, cmd.IP, cmd.App, cmd.Cmd, cmd.Args,
		cmd.UCpu, cmd.SCpu, cmd.DiskIn, cmd.DiskOut,
		cmd.IpcIn, cmd.IpcOut, cmd.MaxRss, cmd.PageFaults, cmd.MemMB, cmd.MemPeakMB, cmd.RPCMsgsIn, cmd.RPCMsgsOut,
		cmd.RPCSizeIn, cmd.RPCSizeOut, cmd.RPCHimarkFwd, cmd.RPCHimarkRev,
		cmd.RPCSnd, cmd.RPCRcv, cmd.Running,
		cmd.NetFilesAdded, cmd.NetFilesUpdated, cmd.NetFilesDeleted,
		cmd.NetBytesAdded, cmd.NetBytesUpdated,
		cmd.LbrRcsOpens, cmd.LbrRcsCloses, cmd.LbrRcsCheckins, cmd.LbrRcsExists,
		cmd.LbrRcsReads, cmd.LbrRcsReadBytes, cmd.LbrRcsWrites, cmd.LbrRcsWriteBytes,
		cmd.LbrRcsDigests, cmd.LbrRcsFileSizes, cmd.LbrRcsModTimes, cmd.LbrRcsCopies,
		cmd.LbrBinaryOpens, cmd.LbrBinaryCloses, cmd.LbrBinaryCheckins, cmd.LbrBinaryExists,
		cmd.LbrBinaryReads, cmd.LbrBinaryReadBytes, cmd.LbrBinaryWrites, cmd.LbrBinaryWriteBytes,
		cmd.LbrBinaryDigests, cmd.LbrBinaryFileSizes, cmd.LbrBinaryModTimes, cmd.LbrBinaryCopies,
		cmd.LbrCompressOpens, cmd.LbrCompressCloses, cmd.LbrCompressCheckins, cmd.LbrCompressExists,
		cmd.LbrCompressReads, cmd.LbrCompressReadBytes, cmd.LbrCompressWrites, cmd.LbrCompressWriteBytes,
		cmd.LbrCompressDigests, cmd.LbrCompressFileSizes, cmd.LbrCompressModTimes, cmd.LbrCompressCopies,
		cmd.LbrUncompressOpens, cmd.LbrUncompressCloses, cmd.LbrUncompressCheckins, cmd.LbrUncompressExists,
		cmd.LbrUncompressReads, cmd.LbrUncompressReadBytes, cmd.LbrUncompressWrites, cmd.LbrUncompressWriteBytes,
		cmd.LbrUncompressDigests, cmd.LbrUncompressFileSizes, cmd.LbrUncompressModTimes, cmd.LbrUncompressCopies,
		cmd.CmdError)
	for _, t := range cmd.Tables {
		rows++
		fmt.Fprintf(f, "INSERT INTO tableuse VALUES ("+
			`"%s",%d,"%s",%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%.3f);`+"\n",
			cmd.GetKey(), cmd.LineNo, t.TableName, t.PagesIn, t.PagesOut, t.PagesCached,
			t.PagesSplitInternal, t.PagesSplitLeaf,
			t.ReadLocks, t.WriteLocks, t.GetRows, t.PosRows, t.ScanRows, t.PutRows, t.DelRows,
			t.TotalReadWait, t.TotalReadHeld, t.TotalWriteWait, t.TotalWriteHeld,
			t.MaxReadWait, t.MaxReadHeld, t.MaxWriteWait, t.MaxWriteHeld, t.PeekCount,
			t.TotalPeekWait, t.TotalPeekHeld, t.MaxPeekWait, t.MaxPeekHeld, t.TriggerLapse)
	}
	return int64(rows)
}

func byteCountDecimal(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "kMGTPE"[exp])
}

func readerFromFile(file *os.File) (io.Reader, int64, error) {
	//create a bufio.Reader so we can 'peek' at the first few bytes
	bReader := bufio.NewReader(file)
	testBytes, err := bReader.Peek(64) //read a few bytes without consuming
	if err != nil {
		return nil, 0, err
	}
	var fileSize int64
	stat, err := file.Stat()
	if err != nil {
		return nil, 0, err
	}
	fileSize = stat.Size()

	// Detect if the content is gzipped
	contentType := http.DetectContentType(testBytes)
	if strings.Contains(contentType, "x-gzip") {
		gzipReader, err := gzip.NewReader(bReader)
		if err != nil {
			return nil, 0, err
		}
		// Estimate filesize
		return gzipReader, fileSize * 20, nil
	}
	return bReader, fileSize, nil
}

// Parse single log file - output is sent via linesChan channel
func parseLog(logger *logrus.Logger, logfile string, linesChan chan string) {
	var file *os.File
	if logfile == "-" {
		file = os.Stdin
	} else {
		var err error
		file, err = os.Open(logfile)
		if err != nil {
			logger.Fatal(err)
		}
	}
	defer file.Close()

	const maxCapacity = 5 * 1024 * 1024
	ctx := context.Background()
	inbuf := make([]byte, maxCapacity)
	reader, fileSize, err := readerFromFile(file)
	if err != nil {
		logger.Fatalf("Failed to open file: %v", err)
	}
	logger.Debugf("Opened %s, size %v", logfile, fileSize)
	reader = bufio.NewReaderSize(reader, maxCapacity)
	preader := progress.NewReader(reader)
	scanner := bufio.NewScanner(preader)
	scanner.Buffer(inbuf, maxCapacity)

	// Start a goroutine printing progress
	go func() {
		d := 1 * time.Second
		if fileSize > 1*1000*1000*1000 {
			d = 10 * time.Second
		}
		if fileSize > 10*1000*1000*1000 {
			d = 30 * time.Second
		}
		if fileSize > 25*1000*1000*1000 {
			d = 60 * time.Second
		}
		logger.Infof("Progress reporting frequency: %v", d)
		progressChan := progress.NewTicker(ctx, preader, fileSize, d)
		for p := range progressChan {
			fmt.Fprintf(os.Stderr, "%s: %s/%s %.0f%% estimated finish %s, %v remaining...\n",
				logfile, byteCountDecimal(p.N()), byteCountDecimal(fileSize),
				p.Percent(), p.Estimated().Format("15:04:05"),
				p.Remaining().Round(time.Second))
		}
		fmt.Fprintln(os.Stderr, "processing completed")
	}()

	const maxLineLen = 5000
	i := 0
	for scanner.Scan() {
		if len(scanner.Text()) > maxLineLen {
			line := fmt.Sprintf("%s...'", scanner.Text()[:maxLineLen])
			linesChan <- line
		} else {
			linesChan <- scanner.Text()
		}
		i += 1
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read input file on line: %d, %v\n", i, err)
	}

}

func getFilename(name, suffix string, requireSuffix bool, logfiles []string) string {
	if name == "" {
		if len(logfiles) == 0 {
			name = "logs"
		} else {
			name = strings.TrimSuffix(logfiles[0], ".gz")
			name = strings.TrimSuffix(name, ".log")
		}
		if !requireSuffix && !strings.HasSuffix(name, suffix) {
			name = fmt.Sprintf("%s%s", name, suffix)
		}
	}
	// Check again
	if requireSuffix && !strings.HasSuffix(name, suffix) {
		name = fmt.Sprintf("%s%s", name, suffix)
	}
	return name
}

func getDBName(name string, logfiles []string) string {
	return getFilename(name, ".db", true, logfiles)
}

func getMetricsFilename(name string, logfiles []string) string {
	return getFilename(name, ".metrics", false, logfiles)
}

func getJSONFilename(name string, logfiles []string) string {
	return getFilename(name, ".json", false, logfiles)
}

func getSQLFilename(name string, logfiles []string) string {
	return getFilename(name, ".sql", false, logfiles)
}

func openFile(outputName string) (*os.File, *bufio.Writer, error) {
	var fd *os.File
	var err error
	if outputName == "-" {
		fd = os.Stdout
	} else {
		fd, err = os.OpenFile(outputName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, nil, err
		}
	}
	return fd, bufio.NewWriterSize(fd, 1024*1024), nil
}

func main() {
	// Tracing code
	// ft, err := os.Create("trace.out")
	// if err != nil {
	// 	panic(err)
	// }
	// defer ft.Close()
	// err = trace.Start(ft)
	// if err != nil {
	// 	panic(err)
	// }
	// defer trace.Stop()
	// End of trace code
	var err error
	var (
		logfiles = kingpin.Arg(
			"logfile",
			"Log files to process.").Strings()
		debug = kingpin.Flag(
			"debug",
			"Enable debugging level.",
		).Int()
		jsonOutput = kingpin.Flag(
			"json",
			"Output JSON statements (to default or --json.output file).",
		).Bool()
		sqlOutput = kingpin.Flag(
			"sql",
			"Output SQL statements (to default or --sql.output file).",
		).Bool()
		jsonOutputFile = kingpin.Flag(
			"json.output",
			"Name of file to which to write JSON if that flag is set. Defaults to <logfile-prefix>.json",
		).String()
		sqlOutputFile = kingpin.Flag(
			"sql.output",
			"Name of file to which to write SQL if that flag is set. Defaults to <logfile-prefix>.sql",
		).String()
		dbName = kingpin.Flag(
			"dbname",
			"Create database with this name. Defaults to <logfile-prefix>.db",
		).Short('d').String()
		noSQL = kingpin.Flag(
			"no.sql",
			"Don't create database.",
		).Short('n').Bool()
		noMetrics = kingpin.Flag(
			"no.metrics",
			"Disable historical metrics output in VictoriaMetrics format (via Graphite interface).",
		).Bool()
		metricsOutputFile = kingpin.Flag(
			"metrics.output",
			"File to write historical metrics to in Graphite format for use with VictoriaMetrics. Default is <logfile-prefix>.metrics",
		).Short('m').String()
		serverID = kingpin.Flag(
			"server.id",
			"server id for historical metrics - useful to identify site.",
		).Short('s').String()
		sdpInstance = kingpin.Flag(
			"sdp.instance",
			"SDP instance if required in historical metrics. (Not usually required)",
		).String()
		updateInterval = kingpin.Flag(
			"update.interval",
			"Update interval for historical metrics - time is assumed to advance as per time in log entries.",
		).Default("10s").Duration()
		noOutputCmdsByUser = kingpin.Flag(
			"no.output.cmds.by.user",
			"Turns off the output of cmds_by_user - can be useful for large sites with many thousands of users.",
		).Default("false").Bool()
		outputCmdsByUserRegex = kingpin.Flag(
			"output.cmds.by.user.regex",
			"Specify a (golang) regex to match user ids in order to track cmds by user in one metric (e.g. '.*' or 'swarm|jenkins').",
		).String()
		noOutputCmdsByIP = kingpin.Flag(
			"no.output.cmds.by.IP",
			"Turns off the output of cmds_by_IP - can be useful for large sites with many thousands of IP addresses in logs.",
		).Default("false").Bool()
		caseInsensitiveServer = kingpin.Flag(
			"case.insensitive.server",
			"Set if server is case insensitive and usernames may occur in either case.",
		).Default("false").Bool()
		debugPID = kingpin.Flag(
			"debug.pid",
			"Set for debug output for specified PID - requires debug.cmd to be also specified.",
		).Int64()
		debugCmd = kingpin.Flag(
			"debug.cmd",
			"Set for debug output for specified command - requires debug.pid to be also specified.",
		).Default("").String()
	)
	kingpin.UsageTemplate(kingpin.CompactUsageTemplate).Version(version.Print("log2sql")).Author("Robert Cowham")
	kingpin.CommandLine.Help = "Parses one or more p4d text log files (which may be gzipped) into a Sqlite3 database and/or JSON or SQL format.\n" +
		"The output of historical Prometheus compatible metrics is also by default." +
		"These can be viewed using VictoriaMetrics which is a Prometheus compatible data store, and viewed in Grafana. " +
		"Where referred to in help <logfile-prefix> is the first logfile specified with any .gz or .log suffix removed."
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	// Validate regex
	if _, err := regexp.Compile(*outputCmdsByUserRegex); err != nil {
		fmt.Printf("ERROR: Failed to parse parameter '%s' as a valid Go regex\n", *outputCmdsByUserRegex)
		os.Exit(1)
	}

	if *debug > 0 {
		// CPU profiling by default
		defer profile.Start().Stop()
	}
	logger := logrus.New()
	logger.Level = logrus.InfoLevel
	if *debug > 0 {
		logger.Level = logrus.DebugLevel
	}
	if *debug >= int(p4dlog.DebugCommands) {
		logger.Level = logrus.TraceLevel
	}
	startTime := time.Now()
	logger.Infof("%v", version.Print("log2sql"))
	logger.Infof("Starting %s, Logfiles: %v", startTime, *logfiles)
	logger.Infof("Flags: debug %v, json/file %v/%v, sql/file %v/%v, dbName %s, noMetrics/file %v/%v",
		*debug, *jsonOutput, *jsonOutputFile, *sqlOutput, *sqlOutputFile, *dbName, *noMetrics, *metricsOutputFile)
	logger.Infof("       serverID %v, sdpInstance %v, updateInterval %v, noOutputCmdsByUser %v, outputCmdsByUserRegex %s caseInsensitve %v, debugPID/cmd %v/%s",
		*serverID, *sdpInstance, *updateInterval, *noOutputCmdsByUser, *outputCmdsByUserRegex, *caseInsensitiveServer, *debugPID, *debugCmd)

	linesChan := make(chan string, 10000)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mconfig := &metrics.Config{
		Debug:                 *debug,
		ServerID:              *serverID,
		SDPInstance:           *sdpInstance,
		UpdateInterval:        *updateInterval,
		OutputCmdsByUser:      !*noOutputCmdsByUser,
		OutputCmdsByUserRegex: *outputCmdsByUserRegex,
		OutputCmdsByIP:        !*noOutputCmdsByIP,
		CaseSensitiveServer:   !*caseInsensitiveServer,
	}

	var fJSON, fSQL, fMetrics *bufio.Writer
	var fdJSON, fdSQL, fdMetrics *os.File
	var jsonFilename, sqlFilename, metricsFilename string
	if *jsonOutput {
		jsonFilename = getJSONFilename(*jsonOutputFile, *logfiles)
		fdJSON, fJSON, err = openFile(jsonFilename)
		if err != nil {
			logger.Fatal(err)
		}
		defer fdJSON.Close()
		defer fJSON.Flush()
		logger.Infof("Creating JSON output: %s", jsonFilename)
	}
	if *sqlOutput {
		sqlFilename = getSQLFilename(*sqlOutputFile, *logfiles)
		fdSQL, fSQL, err = openFile(sqlFilename)
		if err != nil {
			logger.Fatal(err)
		}
		defer fdSQL.Close()
		defer fSQL.Flush()
		logger.Infof("Creating SQL output: %s", sqlFilename)
	}
	writeMetrics := !*noMetrics
	if writeMetrics {
		metricsFilename = getMetricsFilename(*metricsOutputFile, *logfiles)
		fdMetrics, fMetrics, err = openFile(metricsFilename)
		if err != nil {
			logger.Fatal(err)
		}
		defer fdMetrics.Close()
		defer fMetrics.Flush()
		logger.Infof("Creating metrics output: %s, config: %+v", metricsFilename, mconfig)
	}

	writeDB := !*noSQL
	var db *sqlite3.Conn
	if writeDB {
		name := getDBName(*dbName, *logfiles)
		logger.Infof("Creating database: %s", name)
		var err error
		db, err = sqlite3.Open(name)
		if err != nil {
			logger.Fatal(err)
		}
		defer db.Close()
	}

	var wg sync.WaitGroup
	var mp *metrics.P4DMetrics
	var fp *p4dlog.P4dFileParser
	var metricsChan chan string
	var cmdChan chan p4dlog.Command
	needCmdChan := writeDB || *sqlOutput || *jsonOutput

	logger.Debugf("Metrics: %v, needCmdChan: %v", writeMetrics, needCmdChan)

	if writeMetrics {
		wg.Add(1)
		logger.Debugf("Main: creating metrics")
		mp = metrics.NewP4DMetricsLogParser(mconfig, logger, true)
		if *debug != 0 {
			mp.SetDebugMode(*debug)
		}
		if *debugPID != 0 && *debugCmd != "" {
			mp.SetDebugPID(*debugPID, *debugCmd)
		}
		cmdChan, metricsChan = mp.ProcessEvents(ctx, linesChan, needCmdChan)

		// Process all metrics - need to consume them even if we ignore them (overhead is minimal)
		go func() {
			defer wg.Done()
			for metric := range metricsChan {
				fMetrics.Write([]byte(metric))
			}
			logger.Infof("Main: metrics closed")
		}()

	} else {
		fp = p4dlog.NewP4dFileParser(logger)
		if *debugPID != 0 && *debugCmd != "" {
			fp.SetDebugPID(*debugPID, *debugCmd)
		}
		if *debug > 0 {
			fp.SetDebugMode(*debug)
		}
		cmdChan = fp.LogParser(ctx, linesChan, nil)
	}

	// Process all input files, sending lines into linesChan
	wg.Add(1)
	go func() {
		defer wg.Done()

		for _, f := range *logfiles {
			logger.Infof("Processing: %s", f)
			parseLog(logger, f, linesChan)
		}
		logger.Infof("Finished all log files")
		close(linesChan)
	}()

	if needCmdChan {
		var stmtProcess, stmtTableuse *sqlite3.Stmt
		if *sqlOutput {
			writeHeader(fSQL)
			startTransaction(fSQL)
		}
		if writeDB {
			stmt := new(bytes.Buffer)
			writeHeader(stmt)
			// startTransaction(stmt)
			err = db.Exec(stmt.String())
			if err != nil {
				logger.Fatalf("%q: %s", err, stmt)
				return
			}
			stmtProcess, err = db.Prepare(getProcessStatement())
			if err != nil {
				logger.Fatalf("Error preparing statement: %v", err)
			}
			stmtTableuse, err = db.Prepare(getTableUseStatement())
			if err != nil {
				logger.Fatalf("Error preparing statement: %v", err)
			}
			err = db.Begin()
			if err != nil {
				fmt.Println(err)
			}
		}

		i := int64(1)
		for cmd := range cmdChan {
			if p4dlog.FlagSet(*debug, p4dlog.DebugDatabase) {
				logger.Debugf("Main processing cmd: %v", cmd.String())
			}
			if *jsonOutput {
				if p4dlog.FlagSet(*debug, p4dlog.DebugJSON) {
					logger.Debugf("outputting JSON")
				}
				fmt.Fprintf(fJSON, "%s\n", cmd.String())
			}
			if *sqlOutput {
				if p4dlog.FlagSet(*debug, p4dlog.DebugDatabase) {
					logger.Debugf("writing SQL")
				}
				i += writeSQL(fSQL, &cmd)
			}
			if writeDB {
				if p4dlog.FlagSet(*debug, p4dlog.DebugDatabase) {
					logger.Debugf("writing to DB")
				}
				j := preparedInsert(logger, stmtProcess, stmtTableuse, &cmd)
				if !*sqlOutput { // Avoid double counting
					i += j
				}
			}
			if i >= statementsPerTransaction && (*sqlOutput || writeDB) {
				if *sqlOutput {
					writeTransaction(fSQL)
				}
				if writeDB {
					err = db.Commit()
					if err != nil {
						logger.Errorf("commit error: %v", err)
					}
					err = db.Begin()
					if err != nil {
						fmt.Println(err)
					}
				}
				i = 1
			}
		}
		if *sqlOutput {
			writeTrailer(fSQL)
		}
		if writeDB {
			err = db.Commit()
			if err != nil {
				logger.Errorf("commit error: %v", err)
			}
		}
	}

	wg.Wait()
	logger.Infof("Completed %s, elapsed %s", time.Now(), time.Since(startTime))
}
