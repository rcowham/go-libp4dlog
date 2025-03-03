package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/machinebox/progress"
	"github.com/sirupsen/logrus"

	// "github.com/pkg/profile"

	"github.com/perforce/p4prometheus/version"
	p4dlog "github.com/rcowham/go-libp4dlog"
)

// GO standard reference value/format: Mon Jan 2 15:04:05 -0700 MST 2006
const p4timeformat = "2006/01/02 15:04:05"

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

// P4Pending structure
type P4Pending struct {
	debug              int
	fp                 *p4dlog.P4dFileParser
	logger             *logrus.Logger
	linesChan          chan string
	totalCount         int
	pendingCount       int
	timeLatestStartCmd time.Time
	latestStartCmdBuf  string
	timeChan           chan time.Time
}

// Searches for log lines starting with a <tab>date - assumes increasing dates in log
func (p4p *P4Pending) processTimePassing(line string) bool {
	// This next section is more efficient than regex parsing - we return ASAP
	const lenPrefix = len("\t2020/03/04 12:13:14")
	if len(line) < lenPrefix {
		return false
	}
	// Check for expected chars at specific points
	if line[0] != '\t' || line[5] != '/' || line[8] != '/' ||
		line[11] != ' ' || line[14] != ':' || line[17] != ':' {
		return false
	}
	// Check for digits
	for _, i := range []int{1, 2, 3, 4, 6, 7, 9, 10, 12, 13, 15, 16, 18, 19} {
		if line[i] < byte('0') || line[i] > byte('9') {
			return false
		}
	}
	if len(p4p.latestStartCmdBuf) == 0 {
		p4p.latestStartCmdBuf = line[:lenPrefix]
		p4p.timeLatestStartCmd, _ = time.Parse(p4timeformat, line[1:lenPrefix])
		return false
	}
	if len(p4p.latestStartCmdBuf) > 0 && p4p.latestStartCmdBuf == line[:lenPrefix] {
		return false
	}
	// Update only if greater (due to log format we do see out of sequence dates with track records)
	if strings.Compare(line[:lenPrefix], p4p.latestStartCmdBuf) <= 0 {
		return false
	}
	dt, _ := time.Parse(p4timeformat, string(line[1:lenPrefix]))
	if dt.Sub(p4p.timeLatestStartCmd) >= 1*time.Second {
		if p4p.debug != 0 {
			p4p.logger.Debugf("Updating pending time to %v", dt)
		}
		p4p.timeChan <- dt
	}
	if dt.Sub(p4p.timeLatestStartCmd) >= 1*time.Second {
		p4p.timeLatestStartCmd = dt
		p4p.latestStartCmdBuf = line[:lenPrefix]
		return true
	}
	return false
}

// Parse single log file - output is sent via linesChan channel
func (p4p *P4Pending) parseLog(logfile string) {
	var file *os.File
	if logfile == "-" {
		file = os.Stdin
	} else {
		var err error
		file, err = os.Open(logfile)
		if err != nil {
			p4p.logger.Fatal(err)
		}
	}
	defer file.Close()

	const maxCapacity = 5 * 1024 * 1024
	ctx := context.Background()
	inbuf := make([]byte, maxCapacity)
	reader, fileSize, err := readerFromFile(file)
	if err != nil {
		p4p.logger.Fatalf("Failed to open file: %v", err)
	}
	p4p.logger.Debugf("Opened %s, size %v", logfile, fileSize)
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
		p4p.logger.Infof("Progress reporting frequency: %v", d)
		progressChan := progress.NewTicker(ctx, preader, fileSize, d)
		for p := range progressChan {
			fmt.Fprintf(os.Stderr, "%s: %s/%s %.0f%% estimated finish %s, %v remaining... cmds total %d, pending %d\n",
				logfile, byteCountDecimal(p.N()), byteCountDecimal(fileSize),
				p.Percent(), p.Estimated().Format("15:04:05"),
				p.Remaining().Round(time.Second),
				p4p.totalCount, p4p.pendingCount)
		}
		fmt.Fprintln(os.Stderr, "processing completed")
	}()

	const maxLine = 10000
	i := 0
	for scanner.Scan() {
		// Use time records in log to cause ticks for log parser
		if len(scanner.Text()) > maxLine {
			line := fmt.Sprintf("%s...'", scanner.Text()[0:maxLine])
			// p4p.processTimePassing(line)
			p4p.linesChan <- line
		} else {
			line := scanner.Text()
			// p4p.processTimePassing(line)
			p4p.linesChan <- line
		}
		i += 1
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read input file on line: %d, %v\n", i, err)
	}

}

func (p4p *P4Pending) processEvents(logfiles []string) {

	for _, f := range logfiles {
		p4p.logger.Infof("Processing: %s", f)
		p4p.parseLog(f)
	}
	p4p.logger.Infof("Finished all log files")
	close(p4p.linesChan)

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

func getJSONFilename(name string, logfiles []string) string {
	return getFilename(name, ".json", false, logfiles)
}

func openFile(outputName string) (*os.File, *bufio.Writer, error) {
	var fd *os.File
	var err error
	if outputName == "-" {
		fd = os.Stdout
	} else {
		fd, err = os.OpenFile(outputName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
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
		jsonOutputFile = kingpin.Flag(
			"json.output",
			"Name of file to which to write JSON if that flag is set. Defaults to <logfile-prefix>.json",
		).String()
		debugPID = kingpin.Flag(
			"debug.pid",
			"Set for debug output for specified PID - requires debug.cmd to be also specified.",
		).Int64()
		debugCmd = kingpin.Flag(
			"debug.cmd",
			"Set for debug output for specified command - requires debug.pid to be also specified.",
		).Default("").String()
	)
	kingpin.UsageTemplate(kingpin.CompactUsageTemplate).Version(version.Print("p4dpending")).Author("Robert Cowham")
	kingpin.CommandLine.Help = "Parses one or more p4d text log files (which may be gzipped) and lists pending commands.\n" +
		"Commands are produced in reverse chronological order."
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	// if *debug > 0 {
	// 	// CPU profiling by default
	// 	// defer profile.Start().Stop()
	// }
	logger := logrus.New()
	logger.Level = logrus.InfoLevel
	if *debug > 0 {
		logger.Level = logrus.DebugLevel
	}
	startTime := time.Now()
	logger.Infof("%v", version.Print("p4dpending"))
	logger.Infof("Starting %s, Logfiles: %v", startTime, *logfiles)
	logger.Infof("Flags: debug %v, jsonfile %v, debugPid/cmd %d/%s", *debug, *jsonOutputFile, *debugPID, *debugCmd)

	linesChan := make(chan string, 10000)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var fJSON *bufio.Writer
	var fdJSON *os.File
	jsonFilename := getJSONFilename(*jsonOutputFile, *logfiles)
	fdJSON, fJSON, err = openFile(jsonFilename)
	if err != nil {
		logger.Fatal(err)
	}
	defer fdJSON.Close()
	defer fJSON.Flush()
	logger.Infof("Creating JSON output: %s", jsonFilename)

	var wg sync.WaitGroup
	var fp *p4dlog.P4dFileParser
	var cmdChan chan interface{}

	fp = p4dlog.NewP4dFileParser(logger)
	p4p := &P4Pending{
		debug:     *debug,
		logger:    logger,
		fp:        fp,
		linesChan: linesChan,
		timeChan:  make(chan time.Time, 1000),
	}
	if *debug > 0 {
		fp.SetDebugMode(*debug)
	}
	if *debug >= int(p4dlog.DebugCommands) {
		logger.Level = logrus.TraceLevel
	}
	if *debugPID != 0 && *debugCmd != "" {
		fp.SetDebugPID(*debugPID, *debugCmd)
	}
	// cmdChan = fp.LogParser(ctx, linesChan, p4p.timeChan)
	cmdChan = fp.LogParser(ctx, linesChan, nil)

	// Process all input files, sending lines into linesChan
	wg.Add(1)

	go func() {
		defer wg.Done()
		p4p.processEvents(*logfiles)
	}()

	// Process all commands, but discarding those with completion records
	// When we close the linesChan above, we will force the output of "pending" commands.
	for cmd := range cmdChan {
		switch cmd := cmd.(type) {
		case p4dlog.Command:
			p4p.totalCount += 1
			if cmd.EndTime.IsZero() {
				p4p.pendingCount += 1
				fmt.Fprintf(fJSON, "%s\n", cmd.String())
			} else {
				if p4p.totalCount%100000 == 0 {
					fJSON.Flush()
				}
			}
		case p4dlog.ServerEvent:
			p4p.totalCount += 1
		}
	}

	wg.Wait()
	logger.Infof("Completed %s, elapsed %s, cmds total %d, pending %d",
		time.Now(), time.Since(startTime), p4p.totalCount, p4p.pendingCount)
}
