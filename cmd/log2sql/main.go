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
	"strings"
	"sync"
	"time"

	"github.com/bvinc/go-sqlite-lite/sqlite3"
	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/machinebox/progress"
	"github.com/sirupsen/logrus"

	// "github.com/pkg/profile"

	"github.com/perforce/p4prometheus/version"
	p4dlog "github.com/rcowham/go-libp4dlog"
	"github.com/rcowham/go-libp4dlog/metrics"
)

const statementsPerTransaction = 50 * 1000

func writeHeader(f io.Writer) {
	fmt.Fprintf(f, `CREATE TABLE IF NOT EXISTS process
	(processkey CHAR(50) NOT NULL, lineNumber INT NOT NULL, pid INT NOT NULL, 
	startTime DATETIME NOT NULL,endTime DATETIME NULL, computedLapse FLOAT NULL,completedLapse FLOAT NULL,
	user TEXT NOT NULL, workspace TEXT NOT NULL, ip TEXT NOT NULL, app TEXT NOT NULL, cmd TEXT NOT NULL,
	args TEXT NULL, uCpu INT NULL, sCpu INT NULL, diskIn INT NULL, diskOut INT NULL, ipcIn INT NULL,
	ipcOut INT NULL, maxRss INT NULL, pageFaults INT NULL, rpcMsgsIn INT NULL, rpcMsgsOut INT NULL,
	rpcSizeIn INT NULL, rpcSizeOut INT NULL, rpcHimarkFwd INT NULL, rpcHimarkRev INT NULL,
	rpcSnd FLOAT NULL, rpcRcv FLOAT NULL, running INT NULL,
	error TEXT NULL,
	PRIMARY KEY (processkey, lineNumber));
`)
	fmt.Fprintf(f, `CREATE TABLE IF NOT EXISTS tableUse
	(processkey CHAR(50) NOT NULL, lineNumber INT NOT NULL,
	tableName VARCHAR(255) NOT NULL, pagesIn INT NULL, pagesOut INT NULL, pagesCached INT NULL,
	pagesSplitInternal INT NULL, pagesSplitLeaf INT NULL,
	readLocks INT NULL, writeLocks INT NULL, getRows INT NULL, posRows INT NULL, scanRows INT NULL,
	putRows int NULL, delRows INT NULL, totalReadWait INT NULL, totalReadHeld INT NULL,
	totalWriteWait INT NULL, totalWriteHeld INT NULL, maxReadWait INT NULL, maxReadHeld INT NULL,
	maxWriteWait INT NULL, maxWriteHeld INT NULL, peekCount INT NULL,
	totalPeekWait INT NULL, totalPeekHeld INT NULL, maxPeekWait INT NULL, maxPeekHeld INT NULL,
	triggerLapse FLOAT NULL,
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
		ipcOut, maxRss, pageFaults, rpcMsgsIn, rpcMsgsOut,
		rpcSizeIn, rpcSizeOut, rpcHimarkFwd, rpcHimarkRev,
		rpcSnd, rpcRcv, running, error)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
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
		cmd.IpcIn, cmd.IpcOut, cmd.MaxRss, cmd.PageFaults, cmd.RPCMsgsIn, cmd.RPCMsgsOut,
		cmd.RPCSizeIn, cmd.RPCSizeOut, cmd.RPCHimarkFwd, cmd.RPCHimarkRev,
		float64(cmd.RPCSnd), float64(cmd.RPCRcv), cmd.Running, cmd.CmdError)
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
		`"%s","%s","%s","%s","%s","%s",%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,`+
		`%.3f,%.3f,%d,"%v");`+"\n",
		cmd.GetKey(), cmd.LineNo, cmd.Pid, dateStr(cmd.StartTime), dateStr(cmd.EndTime),
		cmd.ComputeLapse, cmd.CompletedLapse,
		cmd.User, cmd.Workspace, cmd.IP, cmd.App, cmd.Cmd, cmd.Args,
		cmd.UCpu, cmd.SCpu, cmd.DiskIn, cmd.DiskOut,
		cmd.IpcIn, cmd.IpcOut, cmd.MaxRss, cmd.PageFaults, cmd.RPCMsgsIn, cmd.RPCMsgsOut,
		cmd.RPCSizeIn, cmd.RPCSizeOut, cmd.RPCHimarkFwd, cmd.RPCHimarkRev,
		cmd.RPCSnd, cmd.RPCRcv, cmd.Running, cmd.CmdError)
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

	const maxCapacity = 1024 * 1024
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

	for scanner.Scan() {
		linesChan <- scanner.Text()
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
	// CPU profiling by default
	// defer profile.Start().Stop()
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
			"Enable debugging.",
		).Bool()
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

	logger := logrus.New()
	logger.Level = logrus.InfoLevel
	if *debug {
		logger.Level = logrus.DebugLevel
	}
	startTime := time.Now()
	logger.Infof("%v", version.Print("log2sql"))
	logger.Infof("Starting %s, Logfiles: %v", startTime, *logfiles)

	linesChan := make(chan string, 10000)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mconfig := &metrics.Config{
		Debug:               *debug,
		ServerID:            *serverID,
		SDPInstance:         *sdpInstance,
		UpdateInterval:      *updateInterval,
		OutputCmdsByUser:    !*noOutputCmdsByUser,
		CaseSensitiveServer: !*caseInsensitiveServer,
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
		cmdChan, metricsChan = mp.ProcessEvents(ctx, linesChan, needCmdChan)
		if *debugPID != 0 && *debugCmd != "" {
			mp.SetDebugPID(*debugPID, *debugCmd)
		}

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
		cmdChan = fp.LogParser(ctx, linesChan, nil)
		if *debugPID != 0 && *debugCmd != "" {
			fp.SetDebugPID(*debugPID, *debugCmd)
		}
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
			if logger.Level >= logrus.DebugLevel {
				logger.Debugf("Main processing cmd: %v", cmd.String())
			}
			if *jsonOutput {
				logger.Debugf("outputting JSON")
				fmt.Fprintf(fJSON, "%s\n", cmd.String())
			}
			if *sqlOutput {
				logger.Debugf("writing SQL")
				i += writeSQL(fSQL, &cmd)
			}
			if writeDB {
				logger.Debugf("writing to DB")
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
