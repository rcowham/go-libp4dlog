package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/akamensky/argparse"
	"github.com/pkg/profile"
	"github.com/rcowham/go-libp4dlog"
)

type parseResult struct {
	buf      bufio.Writer
	callback p4dlog.P4dOutputCallback
}

func newResult() *parseResult {
	var pr parseResult
	buf := bufio.NewWriterSize(os.Stdout, 1024*1024)
	defer buf.Flush()
	pr.callback = func(output string) {
		fmt.Fprintf(buf, "%s\n", output)
	}
	return &pr
}

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
	presult := newResult()
	fp := p4dlog.NewP4dFileParser(presult.callback)
	fp.P4LogParseFile(*opts)
}
