package main

// This command line utility wraps up p4d log analyzer
import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	p4dlog "github.com/rcowham/go-libp4dlog"
	"github.com/rcowham/go-libtail/tailer"
	"github.com/rcowham/go-libtail/tailer/fswatcher"
	"github.com/rcowham/go-libtail/tailer/glob"

	"github.com/sirupsen/logrus"
)

var blankTime time.Time

var (
	logpath    = flag.String("logpath", "/p4/1/logs/log", "Path to the p4d log file to tail.")
	outputpath = flag.String("output", "-", "Output - Prometheus metrics file or blank/'-' for stdout")
)

// Structure for use with libtail
type logConfig struct {
	Type                 string
	Path                 string
	PollInterval         time.Duration
	Readall              bool
	FailOnMissingLogfile bool
}

// P4Prometheus structure
type P4Prometheus struct {
	logFilename    string
	outputFilename string
	logger         *logrus.Logger
	cmdCounter     map[string]int32
	cmdCumulative  map[string]float64
	lines          chan []byte
	events         chan string
	lastOutputTime time.Time
}

func newP4Prometheus(logFilename, outputFilename string, logger *logrus.Logger) (p4p *P4Prometheus) {
	return &P4Prometheus{
		logFilename:    logFilename,
		outputFilename: outputFilename,
		logger:         logger,
		lines:          make(chan []byte, 100),
		events:         make(chan string, 100),
		cmdCounter:     make(map[string]int32),
		cmdCumulative:  make(map[string]float64),
	}
}

func (p4p *P4Prometheus) publishCumulative() {
	if p4p.lastOutputTime == blankTime || time.Now().Sub(p4p.lastOutputTime) >= time.Second*10 {
		tmpfile, err := ioutil.TempFile("", "~output")
		if err != nil {
			p4p.logger.Fatal(err)
		}
		f, err := os.Create(tmpfile.Name())
		if err != nil {
			p4p.logger.Fatal(err)
		}
		p4p.logger.Infof("Temp file: %s\n", tmpfile.Name())
		p4p.lastOutputTime = time.Now()
		fmt.Fprintf(f, "# HELP p4_cmd_counter A count of completed p4 cmds (by cmd)\n"+
			"# TYPE p4_cmd_counter counter\n")
		for cmd, count := range p4p.cmdCounter {
			fmt.Fprintf(f, "p4_cmd_counter{cmd=\"%s\"} %d\n", cmd, count)
		}
		fmt.Fprintf(f, "# HELP p4_cmd_cumulative_seconds The total in seconds (by cmd)\n"+
			"# TYPE p4_cmd_cumulative_seconds counter\n")
		for cmd, lapse := range p4p.cmdCumulative {
			fmt.Fprintf(f, "p4_cmd_cumulative_seconds{cmd=\"%s\"} %0.3f\n", cmd, lapse)
		}
		f.Close()
		os.Rename(tmpfile.Name(), p4p.outputFilename)
		os.Chmod(p4p.outputFilename, 0644)
	}
}

func (p4p *P4Prometheus) publishEvent(str string) {
	var f interface{}
	err := json.Unmarshal([]byte(str), &f)
	if err != nil {
		fmt.Printf("Error %v to unmarshal %s", err, str)
	}
	m := f.(map[string]interface{})
	fmt.Printf("%v\n", m)
	fmt.Printf("cmd{\"%s\"}=%0.3f\n", m["cmd"], m["completedLapse"])
	var cmd string
	var ok bool
	if cmd, ok = m["cmd"].(string); !ok {
		fmt.Printf("Failed string: %v", m["cmd"])
		return
	}
	var lapse float64
	if lapse, ok = m["completedLapse"].(float64); !ok {
		fmt.Printf("Failed float: %v", m["completedLapse"])
		return
	}

	p4p.cmdCounter[cmd]++
	p4p.cmdCumulative[cmd] += lapse
	p4p.publishCumulative()

	// 		"p4.cmd":           m["cmd"],
	// 		"p4.user":          m["user"],
	// 		"p4.workspace":     m["workspace"],
	// 		"p4.ip":            m["ip"],
	// 		"p4.args":          m["args"],
	// 		"p4.start_time":    m["startTime"],
	// 		"p4.end_time":      m["endTime"],
	// 		"p4.compute_sec":   m["computeLapse"],
	// 		"p4.completed_sec": m["completedLapse"],
}

func (p4p *P4Prometheus) processEvents() {
	for {
		select {
		case json := <-p4p.events:
			p4p.publishEvent(json)
		default:
			return
		}
	}
}

func startTailer(cfgInput *logConfig, logger *logrus.Logger) (fswatcher.FileTailer, error) {

	var tail fswatcher.FileTailer
	g, err := glob.FromPath(cfgInput.Path)
	if err != nil {
		return nil, err
	}
	switch {
	case cfgInput.Type == "file":
		if cfgInput.PollInterval == 0 {
			tail, err = fswatcher.RunFileTailer([]glob.Glob{g}, cfgInput.Readall, cfgInput.FailOnMissingLogfile, logger)
		} else {
			tail, err = fswatcher.RunPollingFileTailer([]glob.Glob{g}, cfgInput.Readall, cfgInput.FailOnMissingLogfile, cfgInput.PollInterval, logger)
		}
	case cfgInput.Type == "stdin":
		tail = tailer.RunStdinTailer()
	default:
		return nil, fmt.Errorf("Config error: Input type '%v' unknown.", cfgInput.Type)
	}
	return tail, nil
}

func exitOnError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err.Error())
		os.Exit(-1)
	}
}

func main() {
	flag.Parse()

	logger := logrus.New()
	logger.Level = logrus.InfoLevel

	p4p := newP4Prometheus(*logpath, *outputpath, logger)
	logger.Infof("Processing log file: %s\n", *logpath)

	fp := p4dlog.NewP4dFileParser()
	go fp.LogParser(p4p.lines, p4p.events)

	//---------------

	cfg := &logConfig{
		Type:                 "file",
		Path:                 *logpath,
		PollInterval:         0,
		Readall:              true,
		FailOnMissingLogfile: true,
	}

	tail, err := startTailer(cfg, logger)
	exitOnError(err)

	lineNo := 0
	for {
		select {
		case <-time.After(time.Second * 1):
			p4p.processEvents()
			p4p.publishCumulative()
		case err := <-tail.Errors():
			if os.IsNotExist(err.Cause()) {
				exitOnError(fmt.Errorf("error reading log lines: %v: use 'fail_on_missing_logfile: false' in the input configuration if you want grok_exporter to start even though the logfile is missing", err))
			} else {
				exitOnError(fmt.Errorf("error reading log lines: %v", err.Error()))
			}
		case line := <-tail.Lines():
			lineNo++
			p4p.lines <- []byte(line.Line)
		case json := <-p4p.events:
			p4p.publishEvent(json)
		}
	}

	// sigs := make(chan os.Signal, 1)
	// done := make(chan bool, 1)

	// // registers to receive notifications of the specified signals.
	// signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// // Block waiting for signals. When it gets one it'll print it out
	// // and then notify the program that it can finish.
	// go func() {
	// 	sig := <-sigs
	// 	fmt.Println()
	// 	fmt.Println(sig)
	// 	done <- true
	// }()

	// // The program will wait here until it gets the
	// // expected signal (as indicated by the goroutine
	// // above sending a value on `done`) and then exit.
	// fmt.Println("awaiting signal")
	// <-done
	// fmt.Println("exiting")
	// stop <- struct{}{}

}
