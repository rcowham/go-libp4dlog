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
	"github.com/pkg/profile"
	"github.com/rcowham/go-libp4dlog/p4plog"
	"github.com/rcowham/kingpin"

	"github.com/machinebox/progress"
	"github.com/sirupsen/logrus"

	// "github.com/pkg/profile"

	"github.com/perforce/p4prometheus/version"
)

const statementsPerTransaction = 50 * 1000

// We use SQL comments which appear if you use ".schema" within Sqlite3 - helpful reminder
func writeHeader(f io.Writer) {
	fmt.Fprintf(f, `CREATE TABLE IF NOT EXISTS p4pcmd -- main process table for p4p syncs
	(lineNumber INT NOT NULL, -- Line no for first occurrence of pid for this command in p4p log
	pid INT NOT NULL, -- Process ID
	endTime DATETIME NULL, -- end time of command
	completedLapse FLOAT NULL, -- Lapse time for total command (secs)
	proxyTotalsSvr INT NULL, proxyTotalsCache INT NULL, -- Count of files from server/proxy cache
	proxyTotalsSvrBytes INT NULL, proxyTotalsCacheBytes INT NULL -- Size of files from server/prox cache
);
`)
	// PRIMARY KEY (lineNumber)
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
	return `INSERT INTO p4pcmd
		(lineNumber, pid,
		endTime, completedLapse,
		proxyTotalsSvr, proxyTotalsCache, proxyTotalsSvrBytes, proxyTotalsCacheBytes)
		VALUES (?,?,?,?,?,?,?,?)`
}

func preparedInsert(logger *logrus.Logger, stmtProcess, stmtTableuse *sqlite3.Stmt, cmd *p4plog.ProxyCommand) int64 {
	rows := 1
	err := stmtProcess.Exec(
		cmd.LineNo, cmd.Pid, dateStr(cmd.EndTime),
		float64(cmd.CompletedLapse),
		cmd.ProxyTotalsSvr, cmd.ProxyTotalsCache, cmd.ProxyTotalsSvrBytes, cmd.ProxyTotalsCacheBytes)
	if err != nil {
		logger.Errorf("Process insert: %v pid %d, lineNo %d",
			err, cmd.Pid, cmd.LineNo)
	}
	return int64(rows)
}

func writeSQL(f io.Writer, cmd *p4plog.ProxyCommand) int64 {
	rows := 1
	fmt.Fprintf(f, `INSERT INTO p4pcmd VALUES (%d,%d,"%s",%0.3f,`+
		`%d,%d,%d,%d,`+"\n",
		cmd.LineNo, cmd.Pid, dateStr(cmd.EndTime),
		cmd.CompletedLapse,
		cmd.ProxyTotalsSvr, cmd.ProxyTotalsCache, cmd.ProxyTotalsSvrBytes, cmd.ProxyTotalsCacheBytes)
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
	)
	kingpin.UsageTemplate(kingpin.CompactUsageTemplate).Version(version.Print("p4plog2sql")).Author("Robert Cowham")
	kingpin.CommandLine.Help = "Parses one or more p4p text log files (which may be gzipped) into a Sqlite3 database and/or JSON or SQL format.\n" +
		"Note the log files need to have been from p4p -v track=1 to get required information."
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	if *debug > 0 {
		// CPU profiling by default
		defer profile.Start().Stop()
	}
	logger := logrus.New()
	logger.Level = logrus.InfoLevel
	if *debug > 0 {
		logger.Level = logrus.DebugLevel
	}
	startTime := time.Now()
	logger.Infof("%v", version.Print("p4plog2sql"))
	logger.Infof("Starting %s, Logfiles: %v", startTime, *logfiles)
	logger.Infof("Flags: debug %v, json/file %v/%v, sql/file %v/%v, dbName %s, noMetrics/file %v/%v",
		*debug, *jsonOutput, *jsonOutputFile, *sqlOutput, *sqlOutputFile, *dbName, *noMetrics, *metricsOutputFile)

	linesChan := make(chan string, 10000)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var fJSON, fSQL *bufio.Writer
	var fdJSON, fdSQL *os.File
	var jsonFilename, sqlFilename string
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
	var fp *p4plog.P4pFileParser
	var cmdChan chan p4plog.ProxyCommand
	needCmdChan := writeDB || *sqlOutput || *jsonOutput

	logger.Debugf("needCmdChan: %v", needCmdChan)

	fp = p4plog.NewP4pFileParser(logger)
	if *debug > 0 {
		fp.SetDebugMode(*debug)
	}
	cmdChan = fp.LogParser(ctx, linesChan)

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
			err = db.Begin()
			if err != nil {
				fmt.Println(err)
			}
		}

		i := int64(1)
		for cmd := range cmdChan {
			if *jsonOutput {
				fmt.Fprintf(fJSON, "%s\n", cmd.String())
			}
			if *sqlOutput {
				i += writeSQL(fSQL, &cmd)
			}
			if writeDB {
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

	wg.Wait()
	logger.Infof("Completed %s, elapsed %s", time.Now(), time.Since(startTime))
}
