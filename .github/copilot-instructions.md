# Copilot Instructions for go-libp4dlog

## Project Overview
This is a **Perforce P4D log parser** written in Go that analyzes Perforce server text logs and outputs structured data (SQLite, JSON, SQL) plus historical metrics for monitoring. It's designed for performance analysis of Perforce servers at enterprise scale.

## Architecture & Components

### Core Library (`p4dlog.go`)
- **Main Parser**: `P4dFileParser` processes P4D text logs line-by-line using goroutines
- **Data Structures**: `Command`, `ServerEvent`, `Table`, `Block` represent parsed log entities
- **Key Pattern**: Text log entries are parsed into structured commands with timing, user, resource usage data
- **Threading**: Multi-threaded parser using channels (`LogParser()` method) - handles 2-3 cores by default

### Command Line Tools (`cmd/`)
1. **log2sql**: Main tool - parses logs → SQLite DB + VictoriaMetrics format
2. **p4dpending**: Analyzes pending/incomplete commands  
3. **p4locks**: Database lock analysis tool
4. **p4plog2sql**: P4P (proxy) log parser

### Metrics Module (`metrics/`)
- Converts parsed commands to **VictoriaMetrics/Prometheus** format
- Historical metrics for Grafana dashboards
- Contains Docker stack for local analysis (VictoriaMetrics + Grafana)

## Critical Workflows

### Building
```bash
# Local development build
make build

# Cross-platform release (requires xgo Docker setup)  
make dist
```

### Testing with Debug Output
```bash
# Standard tests
go test

# Debug specific test with verbose output
go test -run TestRemovedFromMonitorTable -args -debug
```

### SQL Analysis Workflow
- Run `log2sql` to create SQLite database from P4D logs
- Use `sql_report.sh` for pre-built analysis queries (locks, performance bottlenecks)
- Key tables: `process` (commands), `tableUse` (DB operations), `events` (server status)

## Perforce-Specific Patterns

### Log Entry Types
- **Commands**: User operations with timing, CPU, memory, DB locks
- **Server Events**: Thread counts, resource pressure warnings  
- **Completion Records**: Required when `server=3` configurable set
- **Table Use**: Database lock waits/holds per command per table

### Key Configurables
- Must have `server=3` (or higher) for completion records
- Optional `track=1` for detailed table usage stats
- Parser assumes these settings - will panic if `maxRunningCount` exceeded

### SQL Schema Pattern
```sql
-- Main command table with extensive resource metrics
CREATE TABLE process (processkey, pid, startTime, endTime, user, cmd, args, uCpu, sCpu, maxRss, ...)

-- Database operations per command per table  
CREATE TABLE tableUse (processkey, tableName, readLocks, writeLocks, totalReadWait, totalWriteWait, ...)
```

## Code Conventions

### Error Handling
- Uses `logrus` for structured logging throughout
- Panics on parser limits (e.g., too many running commands without completion records)

### Testing Patterns
- Test files contain actual P4D log entries as test data
- Use `parseLogLines()` helper for parsing test inputs
- Flag-based debug output: `go test -args -debug`

### Concurrency
- Channel-based pipeline: file reading → parsing → output generation
- **Never run multiple terminals commands in parallel** - parser state sensitive
- Uses `statementsPerTransaction = 50,000` for SQLite batch inserts

### Dependencies
- **SQLite**: `go-sqlite-lite` for CGO-based DB operations
- **Metrics**: VictoriaMetrics format output (Graphite protocol)
- **Cross-compilation**: Uses `xgo` Docker for CGO builds across platforms

## Integration Points

### VictoriaMetrics/Prometheus Stack
- Outputs `.metrics` files in Graphite format
- Docker compose in `metrics/docker/` for local analysis
- Pre-configured Grafana dashboards included

### Performance Analysis Workflow
1. Configure P4D with `server=3`, `track=1` 
2. Run `log2sql -d output.db p4d.log`
3. Use `sql_report.sh output.db` for canned analysis
4. Import `.metrics` to VictoriaMetrics for time-series analysis

When working on parser logic, always consider the multi-threaded nature and the fact that log entries can arrive out-of-order or incomplete.