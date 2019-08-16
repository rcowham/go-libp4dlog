# go-libp4dlog

go-libp4dlog is a library for Go to parse Perforce p4d text logs.

P4D log files are written to P4LOG, or "p4d -L log". We would normally recommend configurables server=1 and track1
though you need to ensure your log file is regularly rotated.

For outline of how to setup P4LOG:

https://www.perforce.com/manuals/p4sag/Content/P4SAG/DB5-79706.html

# Usage

```go

import p4dlog "github.com/seanhoughton/go-libp4dlog"

func main()  {
    fp, err := os.Open("/path/to/log")
    if err != nil {
        return err
    }

    commands := p4dlog.ParseLog(ctx, fp, false)
    for command := range commands {
        fmt.Printf("Command %s by %s\n", string(command.Cmd), string(Command.User))
    }
}

```


## P4D Log Analysis

See open source project:

* https://swarm.workshop.perforce.com/projects/perforce-software-log-analyzer

Also KB articles:

* https://community.perforce.com/s/article/2514
* https://community.perforce.com/s/article/2525

## Output of this library

This library can output the results of log parsing as JSON (in future SQL statements for SQLite or MySQL).

It is used by:

* https://github.com/rcowham/p4dbeat - Custom Elastic Beat - consumes parsed log records and sends to Elastic stash
* https://github.com/rcowham/p4prometheus - consumes parsed log records and writes Prometheus metrics
