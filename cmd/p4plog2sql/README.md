# p4plog2sql

This tool will parse logs from P4 Proxy (`p4p`) to produce basic information about files synced from the server vs files synced from proxy cache.

This requires `p4p` to have been started with flag `-v track=1`, which then logs lines such as:

    --- proxytotals files/size svr+cache 1+2/3mb+40mb

## Running the tool

This is very similar to `log2sql`.

    p4plog2sql log2025-02-01.log

will produce a `log2025-02-01.db` (stripping off `.gz` and `.log` from name and appending `.db`).

    p4plog2sql -d logs log2025-02-01.log.gz

will create `logs.db` - automatically opening the gzipped log file and processing it.

Also possible to parse multiple log files in one go:

    p4plog2sql -d logs log2025-02-*

To create a single `logs.db` from multiple input files.

## Sample SQL for reporting purposes

The output of this can be graphed (e.g. in Excel).

```
sqlite3 -header logs.db

sqlite> CREATE INDEX idx_date_part ON p4pcmd(substr(endTime, 1, 10));

sqlite> SELECT
            SUBSTR(endTime,1,10) as day,
            count(pid) as CountSyncs,
            sum(proxyTotalsSvr) as SvrFiles,
            sum(proxytotalscache) as ProxyFiles,
            ROUND(sum(proxytotalsSvrBytes) / 1073741824.0, 2) as SvrGB,
            ROUND(sum(proxytotalscachebytes) / 1073741824.0, 2) as CacheGB
        FROM p4pcmd
        GROUP BY day;
```
