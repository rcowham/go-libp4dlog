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
	"time"

	"github.com/bvinc/go-sqlite-lite/sqlite3"
	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/machinebox/progress"
	"github.com/sirupsen/logrus"

	// "github.com/pkg/profile"

	p4dlog "github.com/rcowham/go-libp4dlog"
	"github.com/rcowham/p4prometheus/version"
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
		cmd.IpcIn, cmd.IpcOut, cmd.MaxRss, cmd.PageFaults, cmd.RpcMsgsIn, cmd.RpcMsgsOut,
		cmd.RpcSizeIn, cmd.RpcSizeOut, cmd.RpcHimarkFwd, cmd.RpcHimarkRev,
		float64(cmd.RpcSnd), float64(cmd.RpcRcv), cmd.Running, cmd.CmdError)
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
		cmd.IpcIn, cmd.IpcOut, cmd.MaxRss, cmd.PageFaults, cmd.RpcMsgsIn, cmd.RpcMsgsOut,
		cmd.RpcSizeIn, cmd.RpcSizeOut, cmd.RpcHimarkFwd, cmd.RpcHimarkRev,
		cmd.RpcSnd, cmd.RpcRcv, cmd.Running, cmd.CmdError)
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

	//Detect if the content is gzipped
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

// Parse single log file - output is sent via logparser channel
func parseLog(logger *logrus.Logger, logfile string, inchan chan []byte) {
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
		logger.Infof("Report duration: %v", d)
		progressChan := progress.NewTicker(ctx, preader, fileSize, d)
		for p := range progressChan {
			fmt.Fprintf(os.Stderr, "%s: %s/%s %.0f%% estimated finish %s, %v remaining...\n",
				logfile, byteCountDecimal(p.N()), byteCountDecimal(fileSize),
				p.Percent(), p.Estimated().Format("15:04:05"),
				p.Remaining().Round(time.Second))
		}
	}()

	for scanner.Scan() {
		inchan <- scanner.Bytes()
	}
	fmt.Fprintln(os.Stderr, "\nprocessing completed")

}

func getDBName(name string, logfiles []string) string {
	if name == "" {
		if len(logfiles) == 0 {
			name = "logs"
		} else {
			name = strings.TrimSuffix(logfiles[0], ".gz")
			name = strings.TrimSuffix(name, ".log")
		}
	}
	if !strings.HasSuffix(name, ".db") {
		name = fmt.Sprintf("%s.db", name)
	}
	return name
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
			"Output JSON statements (otherwise SQL).",
		).Bool()
		outputFile = kingpin.Flag(
			"output",
			"Name of file to which to write SQL (or JSON if that flag is set).",
		).Short('o').String()
		dbName = kingpin.Flag(
			"dbname",
			"Create database.",
		).Short('d').String()
		noSQL = kingpin.Flag(
			"no-sql",
			"Don't create database.",
		).Short('n').Bool()
	)
	kingpin.Version(version.Print("p4sla"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	logger := logrus.New()
	logger.Level = logrus.InfoLevel
	if *debug {
		logger.Level = logrus.DebugLevel
	}
	startTime := time.Now()
	logger.Infof("Starting %s, Logfiles: %v", startTime, *logfiles)

	inchan := make(chan []byte, 100)
	cmdchan := make(chan p4dlog.Command, 100)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fp := p4dlog.NewP4dFileParser(logger)
	if *debug {
		fp.SetDebugMode()
	}

	go fp.LogParser(ctx, inchan, cmdchan)

	go func() {
		for _, f := range *logfiles {
			logger.Infof("Processing: %s\n", f)
			parseLog(logger, f, inchan)
		}
		logger.Debugf("Finished all log files\n")
		close(inchan)
	}()

	writeOutput := *outputFile != ""
	var fd *os.File
	var f io.Writer
	// var err error
	if writeOutput {
		if *outputFile == "-" {
			fd = os.Stdout
		} else {
			fd, err = os.OpenFile(*outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				logger.Fatal(err)
			}
		}
		defer fd.Close()
		f = bufio.NewWriterSize(fd, 1024*1024)
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

	// TODO - fix count of statements - might be doubled
	if !*jsonOutput {
		if writeOutput {
			writeHeader(f)
			startTransaction(f)
		}
		if writeDB {
			stmt := new(bytes.Buffer)
			writeHeader(stmt)
			// startTransaction(stmt)
			err = db.Exec(stmt.String())
			if err != nil {
				logger.Fatalf("%q: %s\n", err, stmt)
				return
			}
		}
		stmtProcess, err := db.Prepare(getProcessStatement())
		if err != nil {
			logger.Fatalf("Error preparing statement: %v", err)
		}
		stmtTableuse, err := db.Prepare(getTableUseStatement())
		if err != nil {
			logger.Fatalf("Error preparing statement: %v", err)
		}
		err = db.Begin()
		if err != nil {
			fmt.Println(err)
		}

		i := int64(1)
		for cmd := range cmdchan {
			if writeOutput {
				i += writeSQL(f, &cmd)
			}
			if writeDB {
				i += preparedInsert(logger, stmtProcess, stmtTableuse, &cmd)
			}
			if i >= statementsPerTransaction {
				if writeOutput {
					writeTransaction(f)
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
		if writeOutput {
			writeTrailer(f)
		}
		if writeDB {
			err = db.Commit()
			if err != nil {
				logger.Errorf("commit error: %v", err)
			}
		}
	} else {
		for cmd := range cmdchan {
			fmt.Fprintf(f, "%s\n", cmd.String())
		}
	}

	logger.Infof("Completed %s, elapsed %s", time.Now(), time.Since(startTime))
}
