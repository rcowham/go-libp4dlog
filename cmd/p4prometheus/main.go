package main

// This command line utility wraps up p4d log analyzer
import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/akamensky/argparse"

	p4dlog "github.com/rcowham/go-libp4dlog"
	"github.com/rcowham/go-tail/follower"
)

// P4Prometheus structure
type P4Prometheus struct {
	// done   chan struct{}
	logFilename    string
	outputFilename string
	// config config.Config
	// client beat.Client
	lines  chan []byte
	events chan string
}

func (p4p *P4Prometheus) publishEvent(str string) {
	var f interface{}
	err := json.Unmarshal([]byte(str), &f)
	if err != nil {
		fmt.Printf("Error %v to unmarshal %s", err, str)
	}
	m := f.(map[string]interface{})
	fmt.Printf("%v\n", m)
	fmt.Printf("p4_cmd_seconds{\"%s\"}=%0.3f\n", m["cmd"], m["completedLapse"])
	// event := beat.Event{
	// 	Timestamp: time.Now(),
	// 	Fields: common.MapStr{
	// 		"p4.cmd":           m["cmd"],
	// 		"p4.user":          m["user"],
	// 		"p4.workspace":     m["workspace"],
	// 		"p4.ip":            m["ip"],
	// 		"p4.args":          m["args"],
	// 		"p4.start_time":    m["startTime"],
	// 		"p4.end_time":      m["endTime"],
	// 		"p4.compute_sec":   m["computeLapse"],
	// 		"p4.completed_sec": m["completedLapse"],
	// 	},
	// }
	// p4p.client.Publish(event)
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

func (p4p *P4Prometheus) tailFile(filename string, done chan struct{}, stop chan struct{}) {
	defer func() {
		done <- struct{}{}
	}()

	tailer, err := follower.New(filename, follower.Config{
		Whence: io.SeekStart,
		Offset: 0,
		Reopen: true,
	})
	if err != nil {
		fmt.Printf("ERR: Start tail file failed, err: %v", err)
		return
	}

	fp := p4dlog.NewP4dFileParser()
	go fp.LogParser(p4p.lines, p4p.events)

	lineNo := 0
	for {
		select {
		case <-time.After(time.Second * 1):
			p4p.processEvents()
		case <-stop:
			fmt.Printf("Stopping\n")
			close(p4p.lines)
			p4p.processEvents()
			tailer.Close()
			return
		case line := <-tailer.Lines():
			lineNo++
			// if lineNo%10 == 0 {
			// 	//fmt.Printf("Parsing line:\n%s", line.String())
			// 	//fmt.Printf("Parsing line:%d\n", lineNo)
			// }
			p4p.lines <- line.Bytes()
		case json := <-p4p.events:
			p4p.publishEvent(json)
			// default:
		}
	}

}

func main() {
	// CPU profiling by default
	// defer profile.Start().Stop()
	// Create new parser object
	parser := argparse.NewParser("P4Prometheus", "Perforce Server Log parser - write Prometheus metrics")
	filename := parser.String("f", "file", &argparse.Options{Required: true, Help: "Log file to process"})
	outfile := parser.String("o", "output", &argparse.Options{Required: true, Help: "Prometheus metrics file to write"})
	// Parse input
	if err := parser.Parse(os.Args); err != nil {
		fmt.Print(parser.Usage(err))
	}

	p4p := new(P4Prometheus)
	p4p.outputFilename = *outfile
	fmt.Printf("Processing log file: %s\n", *filename)

	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)

	// `signal.Notify` registers the given channel to
	// receive notifications of the specified signals.
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	tailFileDone := make(chan struct{})
	stop := make(chan struct{})

	p4p.lines = make(chan []byte, 100)
	p4p.events = make(chan string, 100)

	go p4p.tailFile(*filename, tailFileDone, stop)

	// This goroutine executes a blocking receive for
	// signals. When it gets one it'll print it out
	// and then notify the program that it can finish.
	go func() {
		sig := <-sigs
		fmt.Println()
		fmt.Println(sig)
		done <- true
	}()

	// The program will wait here until it gets the
	// expected signal (as indicated by the goroutine
	// above sending a value on `done`) and then exit.
	fmt.Println("awaiting signal")
	<-done
	fmt.Println("exiting")
	stop <- struct{}{}

}
