# go-libp4dlog
go-libp4dlog is a library for Go to parse Perforce p4d text logs.
It can output the results as JSON or SQL statements (for SQLite or MySQL).

# p4prometheus

This is a cmd line utility to continuously parse log files and write a summary to 
a specified Prometheus compatible metrics file which can be handled via node_exporter
textfile collector module.

## Installation

Create a simple service (/etc/systemd/system/) and run the following as say user `perforce`

/usr/local/bin/p4prometheus -config /p4/common/config/p4prometheus.yaml

## Config file

```yaml
log_path:       /p4/1/logs/log
metrics_output: /p4/metrics/cmds.prom
server_id:      
sdp_instance:   1
```

Note that server_id can be explicitly specified or will be automatically read from /p4/<instance>/root/server.id
