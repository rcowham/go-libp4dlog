# go-libp4dlog

go-libp4dlog is a Go language library to parse Perforce p4d text logs, with a command line executable to process them.

- [go-libp4dlog](#go-libp4dlog)
  - [Running the log analyzer](#running-the-log-analyzer)
  - [Examples](#examples)
  - [P4D Log Analysis](#p4d-log-analysis)
  - [Output of this library](#output-of-this-library)
- [Building the log2sql binary](#building-the-log2sql-binary)

P4D log files are written to a file specified by $P4LOG, or via command line flag "p4d -L p4d.log". We would normally recommend you to set p4d configurables server=1 and track=1
though you need to ensure your log file is regularly rotated as it can become quite large quite quickly.

For outline of how to setup P4LOG:

https://www.perforce.com/manuals/p4sag/Content/P4SAG/DB5-79706.html

## Running the log analyzer

The released binaries for this project are available for Linux/Mac/Windows. After downloading you may want to rename to just `log2sql` or (`log2sql.exe` on Windows)

It is a single executable `log2sql` which will parse a text p4d text log file and by default it will generate a Sqlite3 database.

It is considerably faster (but compatible with)
the `log2sql.py` script mentioned below.

Optionally you can get it to produce SQL insert statements which can be used with the sqlite3 CLI, or parsed for MySQL or similar.

```
$ ./log2sql -h
usage: log2sql [<flags>] [<logfile>...]

Flags:
  -h, --help           Show context-sensitive help (also try --help-long and --help-man).
      --debug          Enable debugging.
      --json           Output JSON statements (otherwise SQL).
  -o, --output=OUTPUT  Name of file to which to write SQL (or JSON if that flag is set).
  -d, --dbname=DBNAME  Create database.
  -n, --no-sql         Don't create database.
      --version        Show application version.

Args:
  [<logfile>]  Log files to process.
```

## Examples

    log2sql log2020-02-01.log

will produce a `log2020-02-01.db` (stripping off `.gz` and `.log` from name and appending `.db`)

    log2sql -d logs log2020-02-01.log.gz

will create `logs.db` - automatically opening the gzipped log file and processing it.

Also possible to parse multiple log files in one go:

    log2sql -d logs log2020-02-*

To create a single `logs.db` from multiple input files.

Typically you will want to run it in the background:

    nohup ./log2sql -d logs > out1 &

Run `tail -f out1` to keep an eye on progress.

To write SQL statements to a file without creating a Sqlite db:

    log2sql -o sql.txt -n

Please note it is multi-threaded, and thus will use 2-3 cores if available (placign load on your system). You may wish to consider 
lowering its priority using the `nice` command.

## P4D Log Analysis

See open source project:

* https://swarm.workshop.perforce.com/projects/perforce-software-log-analyzer

In particular log2sql.py mentioned above.

Also KB articles:

* https://community.perforce.com/s/article/2514
* https://community.perforce.com/s/article/2525

## Output of this library

This library can output the results of log parsing as JSON (in future SQL statements for SQLite or MySQL).

It is used by:

* https://github.com/rcowham/p4dbeat - Custom Elastic Beat - consumes parsed log records and sends to Elastic stash
* https://github.com/rcowham/p4prometheus - consumes parsed log records and writes Prometheus metrics

# Building the log2sql binary

See the [Makefile](cmd/log2sql/Makefile):

    make
or

    make dist

The latter will cross compile with xgo (due to CGO Sqlite3 library in use). Before running you will need:

    docker pull karalabe/xgo-latest
