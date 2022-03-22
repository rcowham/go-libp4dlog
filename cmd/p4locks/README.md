# p4locks - P4D Table Locking Analyser

Based on the `go-libp4dlog` library, this tool will parse logs and produce an HTML file with Google Visualisation
Chart.

Check the [releases](https://github.com/rcowham/go-libp4dlog/releases) page for the latest binary releases.

## Credits

Thanks to Daniel Speed @ Zenimax Online Studios https://github.com/Redundancy for the idea and the initial  Javascript implementation.

__*Contents:*__

- [p4locks - P4D Table Locking Analyser](#p4locks---p4d-table-locking-analyser)
  - [Credits](#credits)
  - [Running the lock analyzer](#running-the-lock-analyzer)
  - [Examples](#examples)
- [Building the p4lock binary](#building-the-p4lock-binary)

See [Project README](../../README.md) for instructions as to creating P4LOG files.

## Running the lock analyzer

The released binaries for this project are available for Linux/Mac/Windows. After downloading you may want to rename to just `p4locks` (or `p4locks.exe` on Windows)

It is a single executable `p4locks` which will parse a text p4d text log file and generate a single HTML file
which can be viewed in a browser. This HTML file includes Google Charting library and displays the output visually.

```
$ ./p4locks -h
usage: p4locks [<flags>] [<logfile>...]

Parses one or more p4d text log files (which may be gzipped) and outputs HTML Google Charts timeline with locks. Locks are listed
by table and then pids with read/write wait/held.

Flags:
  -h, --help                     Show context-sensitive help (also try --help-long and --help-man).
      --debug=DEBUG              Enable debugging level.
  -t, --threshold=THRESHOLD      Threshold value below which commands are filtered out (in milliseconds). Default 1000
  -o, --html.output=HTML.OUTPUT  Name of file to which to write HTML. Defaults to <logfile-prefix>.html
      --version                  Show application version.

Args:
  [<logfile>]  Log files to process.
```

## Examples

    p4locks log2020-02-01.log

will produce a `log2020-02-01.html` (stripping off `.gz` and `.log` from name and appending `.html`).

Also possible to parse multiple log files in one go:

    p4locks -o logs.html log2020-02-*

# Building the p4lock binary

See the [Makefile](Makefile):

    make
or

    make dist

The latter will cross compile to create gzipped output files in the `bin` directory.
