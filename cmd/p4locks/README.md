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
    - [Filtering uninteresting records](#filtering-uninteresting-records)
- [Building the p4lock binary](#building-the-p4lock-binary)

See [Project README](../../README.md) for instructions as to creating P4LOG files.

## Running the lock analyzer

The released binaries for this project are available for Linux/Mac/Windows. After downloading you may want to rename to just `p4locks` (or `p4locks.exe` on Windows)

It is a single executable `p4locks` which will parse a text p4d text log file and generate a single HTML file
which can be viewed in a browser. This HTML file includes Google Charting library and displays the output visually.

```
$ ./p4locks -h
usage: p4locks [<flags>] [<logfile>...]

Parses one or more p4d text log files (which may be gzipped) and outputs an HTML file with a Google Charts timeline with
information about locks. Locks are listed by table and then pids with read/write wait/held. The output file can be opened locally
by any browser (although internet access required to download JS).

Examples: p4locks -x user log

Flags:
  -h, --help                     Show context-sensitive help (also try --help-long and --help-man).
      --debug=DEBUG              Enable debugging level.
  -t, --threshold=THRESHOLD      Threshold value below which commands are filtered out (in milliseconds). Default 10000
  -o, --html.output=HTML.OUTPUT  Name of file to which to write HTML. Defaults to <logfile-prefix>.html
  -x, --exclude.tables=EXCLUDE.TABLES
                                 Specify a (golang) regex to match tables to exclude from results (e.g. 'user$' or
                                 '(user|nameval)$'). No default.
      --version                  Show application version.

Args:
  [<logfile>]  Log files to process.
```

## Examples

    p4locks log2020-02-01.log

will produce a `log2020-02-01.html` (stripping off `.gz` and `.log` from name and appending `.html`).

Also possible to parse multiple log files in one go:

    p4locks -o logs.html log2020-02-*

Excluding a table (db.user) and setting threshold to 20s for lock wait/held:

    p4locks -t 20000 -x user log

### Filtering uninteresting records

You may find rather large output files which take a long time to load in a browser and contain a lot of uninteresting data.
The easiest way to filter this is to:

* Increase the `threshold` value (filtering out locks wait/held for less time)
* Filter out uninteresting tables

The former is easy via `-t/--threshold`, e.g.

    p4locks -t 30000 log

will leave only commands with lock wait/held > 30s (30,000 ms).

For uninteresting tables, consider counting them and then filtering them out. E.g.

    p4locks -t 30000 log
    grep Table log.html | cut -d',' -f1 | sort | uniq -c | sort -n -k 1,1

You can count the data entries, e.g.

    grep -c Table log.html

Filter out unwanted tables, e.g.

    p4locks -t 30000 -x "(trigger|monitor|group|protect|user|ticket|domain)" log

This will result in a potentially much smaller `log.html` file.

# Building the p4lock binary

See the [Makefile](Makefile):

    make
or

    make dist

The latter will cross compile to create gzipped output files in the `bin` directory.
