# go-libp4dlog

go-libp4dlog is a Go language library to parse Perforce p4d text logs, with a command line executable `log2sql` to process them.

Check the [releases](https://github.com/rcowham/go-libp4dlog/releases) page for the latest binary releases.

* `p4dlog` - log analyzer (this page)
* `p4locks` - lock analyzer - see [p4locks README](cmd/p4locks/README.md)

Contents:

- [go-libp4dlog](#go-libp4dlog)
  - [Running the log analyzer](#running-the-log-analyzer)
  - [Examples](#examples)
  - [Some sample SQL queries](#some-sample-sql-queries)
  - [Viewing historical metrics via Grafana/Prometheus/VictoriaMetrics](#viewing-historical-metrics-via-grafanaprometheusvictoriametrics)
    - [Closing down and removing data](#closing-down-and-removing-data)
  - [P4D Log Analysis](#p4d-log-analysis)
  - [Output of this library](#output-of-this-library)
- [p4locks - lock analyzer](#p4locks---lock-analyzer)
- [Building the log2sql binary](#building-the-log2sql-binary)

P4D log files are written to a file specified by $P4LOG, or via command line flag "p4d -L p4d.log". We would normally 
recommend you to set p4d configurables `server=3` and `track=1` though you need to ensure your log file is regularly rotated as it can become quite large quite quickly.

For outline of how to setup P4LOG:

https://www.perforce.com/manuals/p4sag/Content/P4SAG/DB5-79706.html

## Running the log analyzer

The released binaries for this project are available for Linux/Mac/Windows. After downloading you may want to rename to just `log2sql` (or `log2sql.exe` on Windows)

It is a single executable `log2sql` which will parse a text p4d text log file and by default it will generate a Sqlite3 
database and VictoriaMetrics metrics file (historical metrics). 
For some strange philosophical reason, Prometheus does not provide the ability to import historical data (and is unlikely to ever
have that implemented). Luckily [VictoriaMetrics](https://victoriametrics.com/) is both Prometheus-API compatible as well as being 
more flexible as a long term data store. Highly recommended! 

`log2sql` is considerably faster (but compatible with) the `log2sql.py` script mentioned below.

Optionally you can get it to produce SQL insert statements which can be used with the sqlite3 CLI, or parsed for MySQL or similar.

```
$ ./log2sql -h
usage: log2sql [<flags>] [<logfile>...]

Parses one or more p4d text log files (which may be gzipped) into a Sqlite3 database and/or JSON or SQL format. The output of historical Prometheus compatible
metrics is also by default. These can be viewed using VictoriaMetrics which is a Prometheus compatible data store, and viewed in Grafana. Where referred to in
help <logfile-prefix> is the first logfile specified with any .gz or .log suffix removed.

Flags:
  -h, --help                     Show context-sensitive help (also try --help-long and --help-man).
      --debug                    Enable debugging.
      --json                     Output JSON statements (to default or --json.output file).
      --sql                      Output SQL statements (to default or --sql.output file).
      --json.output=JSON.OUTPUT  Name of file to which to write JSON if that flag is set. Defaults to <logfile-prefix>.json
      --sql.output=SQL.OUTPUT    Name of file to which to write SQL if that flag is set. Defaults to <logfile-prefix>.sql
  -d, --dbname=DBNAME            Create database with this name. Defaults to <logfile-prefix>.db
  -n, --no.sql                   Don't create database.
      --no.metrics               Disable historical metrics output in VictoriaMetrics format (via Graphite interface).
  -m, --metrics.output=METRICS.OUTPUT  
                                 File to write historical metrics to in Graphite format for use with VictoriaMetrics. Default is <logfile-prefix>.metrics
  -s, --server.id=SERVER.ID      server id for historical metrics - useful to identify site.
      --sdp.instance=SDP.INSTANCE  
                                 SDP instance if required in historical metrics. (Not usually required)
      --update.interval=10s      Update interval for historical metrics - time is assumed to advance as per time in log entries.
      --no.output.cmds.by.user   Turns off the output of cmds_by_user - can be useful for large sites with many thousands of users.
      --case.insensitive.server  Set if server is case insensitive and usernames may occur in either case.
      --version                  Show application version.

Args:
  [<logfile>]  Log files to process.
```

## Examples

    log2sql log2020-02-01.log

will produce a `log2020-02-01.db` (stripping off `.gz` and `.log` from name and appending `.db`) and also produce `log2020-02-01.metrics`.

    log2sql -s mysite log2020-02-01.log

will produce same .db as above but sets the `siteid` to "mysite" in the `log2020-02-01.metrics` file.

    log2sql -d logs log2020-02-01.log.gz

will create `logs.db` - automatically opening the gzipped log file and processing it.

Also possible to parse multiple log files in one go:

    log2sql -d logs log2020-02-*

To create a single `logs.db` (and `logs.metrics`) from multiple input files.

Typically you will want to run it in the background if it's going to take a few tens of minutes:

    nohup ./log2sql -d logs > out1 &

Run `tail -f out1` to keep an eye on progress.

To write SQL statements to a file without creating a Sqlite db:

    log2sql --sql -n p4d.log
    log2sql --sql --sql.output sql.txt -n p4d.log

Please note it is multi-threaded, and thus will use 2-3 cores if available (placign load on your system). You may wish to consider 
lowering its priority using the `nice` command.

## Some sample SQL queries

See [log2sql-examples.md](log2sql-examples.md)

## Viewing historical metrics via Grafana/Prometheus/VictoriaMetrics

Also contained within this project are a `docker-compose` environment so that you can run local docker containers, import the historical
metrics, and then connect to Grafana dashboard in order to be able to view them.

* Download a .zip file of this repository
* cd into `metrics/docker` directory

    docker-compose up

The first time will build pre-requisite containers which may take a while.

When it has started you will be able to connect to Grafana on http://localhost:3000.

Default creds:
* login - `admin`
* password - `admin`

Select `skip` to avoid having to change password if you wish to run container for only a short period of time.

Note that the VictoriaMetrics container exposes a port (default `2003`) which you can use to load in your metrics once you have created them:

    cat logfile.metrics | nc localhost 2003

This uses the standard Linux/Mac tool `nc` (netcat).

Then connect to Grafana, select the dashboard `P4 Historical` and view the time frame. Default is the last 6 months, but you should 
use options to narrow down to the time period covered by your log file.

You can review [p4historical.json](dashboards/p4historical.json) or import it into another Grafana setup quite easily (it is auto-installed in this configuration).

### Closing down and removing data

If you just run `docker-compose down` you will stop the containers, but you will not remove any imported data. So if you restart the containers
the metrics you previously imported will still be there.

In order to remove the data volumes so that they are empty next time:

    docker-compose down -v

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
* https://github.com/perforce/p4prometheus - consumes parsed log records and writes Prometheus metrics

# p4locks - lock analyzer

See [p4locks README](cmd/p4locks/README.md)

# Building the log2sql binary

See the [Makefile](cmd/log2sql/Makefile):

    make
or

    make dist

The latter will cross compile with xgo (due to CGO Sqlite3 library in use). Before running you will need:

    docker pull karalabe/xgo-latest
