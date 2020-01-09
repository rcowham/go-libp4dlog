package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"gopkg.in/alecthomas/kingpin.v2"

	// "github.com/pkg/profile"

	p4dlog "github.com/rcowham/go-libp4dlog"
	"github.com/rcowham/p4prometheus/version"
)

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
	readLocks INT NULL, writeLocks INT NULL, getRows INT NULL, posRows INT NULL, scanRows INT NULL,
	putRows int NULL, delRows INT NULL, totalReadWait INT NULL, totalReadHeld INT NULL,
	totalWriteWait INT NULL, totalWriteHeld INT NULL, maxReadWait INT NULL, maxReadHeld INT NULL,
	maxWriteWait INT NULL, maxWriteHeld INT NULL, peekCount INT NULL,
	totalPeekWait INT NULL, totalPeekHeld INT NULL, maxPeekWait INT NULL, maxPeekHeld INT NULL,
	triggerLapse FLOAT NULL,
	PRIMARY KEY (processkey, lineNumber, tableName));
`)
	fmt.Fprintf(f, "PRAGMA journal_mode = MEMORY; \nBEGIN TRANSACTION;\n")
}

func writeTrailer(f io.Writer) {
	fmt.Fprintf(f, "PRAGMA journal_mode = MEMORY; \nEND TRANSACTION;\n")
}

func dateStr(t time.Time) string {
	var blankTime time.Time
	if t == blankTime {
		return ""
	}
	return t.Format("2006/01/02 15:04:05")
}

func writeSQL(f io.Writer, cmd *p4dlog.Command) {
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
		fmt.Fprintf(f, "INSERT INTO tableuse VALUES ("+
			`"%s",%d,"%s",%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%.3f);`+"\n",
			cmd.GetKey(), cmd.LineNo, t.TableName, t.PagesIn, t.PagesOut, t.PagesCached,
			t.ReadLocks, t.WriteLocks, t.GetRows, t.PosRows, t.ScanRows, t.PutRows, t.DelRows,
			t.TotalReadWait, t.TotalReadHeld, t.TotalWriteWait, t.TotalWriteHeld,
			t.MaxReadWait, t.MaxReadHeld, t.MaxWriteWait, t.MaxWriteHeld, t.PeekCount,
			t.TotalPeekWait, t.TotalPeekHeld, t.MaxPeekWait, t.MaxPeekHeld, t.TriggerLapse)
	}
}

func main() {
	// CPU profiling by default
	// defer profile.Start().Stop()
	var (
		logfile = kingpin.Flag(
			"logfile",
			"P4d log file to read (full path).",
		).String()
		debug = kingpin.Flag(
			"debug",
			"Enable debugging.",
		).Bool()
		sql = kingpin.Flag(
			"sql",
			"Output Sqlite statements.",
		).Bool()
	)
	kingpin.Version(version.Print("p4sla"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	inchan := make(chan []byte, 100)
	outchan := make(chan string, 100)
	cmdchan := make(chan p4dlog.Command, 100)

	file, err := os.Open(*logfile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	const maxCapacity = 1024 * 1024
	inbuf := make([]byte, maxCapacity)
	reader := bufio.NewReaderSize(file, maxCapacity)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(inbuf, maxCapacity)

	fp := p4dlog.NewP4dFileParser()
	if *debug {
		fp.SetDebugMode()
	}
	if *sql {
		go fp.LogParser(inchan, cmdchan, outchan)
	} else {
		go fp.LogParser(inchan, nil, outchan)
	}

	go func() {
		for scanner.Scan() {
			inchan <- scanner.Bytes()
		}
		close(inchan)
	}()

	f := bufio.NewWriterSize(os.Stdout, 1024*1024)
	defer f.Flush()
	if *sql {
		writeHeader(f)
		for cmd := range cmdchan {
			writeSQL(f, &cmd)
		}
		writeTrailer(f)
	} else {
		for line := range outchan {
			fmt.Fprintf(f, "%s\n", line)
		}
	}

}
