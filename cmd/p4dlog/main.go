package main

import (
	"bufio"
	"fmt"
	"log"
	"os"

	"gopkg.in/alecthomas/kingpin.v2"

	// "github.com/pkg/profile"

	p4dlog "github.com/rcowham/go-libp4dlog"
	"github.com/rcowham/p4prometheus/version"
)

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
	)
	kingpin.Version(version.Print("p4sla"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	inchan := make(chan []byte, 100)
	outchan := make(chan string, 100)

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
	go fp.LogParser(inchan, nil, outchan)

	go func() {
		for scanner.Scan() {
			inchan <- scanner.Bytes()
		}
		close(inchan)
	}()

	outbuf := bufio.NewWriterSize(os.Stdout, 1024*1024)
	defer outbuf.Flush()
	for line := range outchan {
		fmt.Fprintf(outbuf, "%s\n", line)
	}

}
