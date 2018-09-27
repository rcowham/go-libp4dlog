package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/akamensky/argparse"
	"github.com/pkg/profile"
	"github.com/rcowham/go-libp4dlog"
)

func main() {
	// CPU profiling by default
	defer profile.Start().Stop()
	// Create new parser object
	parser := argparse.NewParser("psla", "Perforce Server Log Analyzer - parses standard log file")
	// Create string flag
	filename := parser.String("f", "file", &argparse.Options{Required: true, Help: "Log file to process"})
	// Parse input
	if err := parser.Parse(os.Args); err != nil {
		fmt.Print(parser.Usage(err))
	}
	opts := new(p4dlog.P4dParseOptions)
	opts.File = *filename
	inchan := make(chan []byte)
	outchan := make(chan string)
	fp := p4dlog.NewP4dFileParser(inchan, outchan)
	go fp.P4LogParseFile(*opts)

	buf := bufio.NewWriterSize(os.Stdout, 1024*1024)
	defer buf.Flush()
	for line := range outchan {
		fmt.Fprintf(buf, "%s\n", line)
	}

}
