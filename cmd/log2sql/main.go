package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/machinebox/progress"
	"github.com/sirupsen/logrus"

	// "github.com/pkg/profile"

	p4dlog "github.com/rcowham/go-libp4dlog"
	"github.com/rcowham/p4prometheus/version"
)

const statementsPerTransaction = 50000

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
	// Trade security for speed - easy to re-run if a problme (hopefully!)
	fmt.Fprintf(f, "PRAGMA journal_mode = OFF;\nPRAGMA synchronous = OFF;\nBEGIN TRANSACTION;\n")
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

// Parse single log file - output is sent via logparser channel
func parseLog(logger *logrus.Logger, logfile string, inchan chan []byte) {
	file, err := os.Open(logfile)
	if err != nil {
		logger.Fatal(err)
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		logger.Fatal(err)
	}
	logger.Debugf("Opened %s, size %v", logfile, stat.Size())

	const maxCapacity = 1024 * 1024
	ctx := context.Background()
	inbuf := make([]byte, maxCapacity)
	reader := bufio.NewReaderSize(file, maxCapacity)
	preader := progress.NewReader(reader)
	scanner := bufio.NewScanner(preader)
	scanner.Buffer(inbuf, maxCapacity)

	// Start a goroutine printing progress
	go func() {
		progressChan := progress.NewTicker(ctx, preader, stat.Size(), 1*time.Second)
		for p := range progressChan {
			fmt.Fprintf(os.Stderr, "\r%s: %s/%s %.0f%% estimated finish %s, %v remaining...",
				logfile, byteCountDecimal(p.N()), byteCountDecimal(stat.Size()),
				p.Percent(), p.Estimated().Format("15:04:05"),
				p.Remaining().Round(time.Second))
		}
	}()

	for scanner.Scan() {
		inchan <- scanner.Bytes()
	}
	fmt.Fprintln(os.Stderr, "\nprocessing completed")

}

func main() {
	// CPU profiling by default
	// defer profile.Start().Stop()
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
	)
	kingpin.Version(version.Print("p4sla"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	logger := logrus.New()
	logger.Level = logrus.InfoLevel
	if *debug {
		logger.Level = logrus.DebugLevel
	}
	logger.Infof("Logfiles: %v", *logfiles)

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

	f := bufio.NewWriterSize(os.Stdout, 1024*1024)
	defer f.Flush()

	if !*jsonOutput {
		writeHeader(f)
		i := int64(1)
		for cmd := range cmdchan {
			i += writeSQL(f, &cmd)
			if i >= statementsPerTransaction {
				writeTransaction(f)
				i = 1
			}
		}
		writeTrailer(f)
	} else {
		for cmd := range cmdchan {
			fmt.Fprintf(f, "%s\n", cmd.String())
		}
	}

}
