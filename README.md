# go-libp4dlog

go-libp4dlog is a library for Go to parse Perforce p4d text logs.

P4D log files are written to P4LOG, or "p4d -L log". We would normally recommend configurables server=1 and track1
though you need to ensure your log file is regularly rotated.

For outline of how to setup P4LOG:

https://www.perforce.com/manuals/p4sag/Content/P4SAG/DB5-79706.html

## Running the log analyzer

The released binaries for this project are available for Linux/Mac/Windows. 

It is a single executable which `log2sql` will parse a text p4d text log file and by default it will generate a Sqlite3 database.

It is considerably faster (but compatible with)
the `log2sql.py` script mentioned below.

Optionally you can get it to produce SQL insert statements which can be used with the sqlite3 CLI, or parsed for MySQL or similar.

## P4D Log Analysis

See open source project:

* https://swarm.workshop.perforce.com/projects/perforce-software-log-analyzer

In particular lgo2sql.py mentioned above.

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
