#!/bin/bash
# Enhanced P4D log analysis via sqlite3 for log2sql
# Provides configurable thresholds and better error handling

# Check bash version - requires bash 4+ for associative arrays
if [[ ${BASH_VERSION%%.*} -lt 4 ]]; then
    echo "Error: This script requires bash version 4.0 or higher for associative array support." >&2
    echo "Current bash version: $BASH_VERSION" >&2
    echo "On macOS, install bash 4+ using: brew install bash" >&2
    echo "Then run with: /usr/local/bin/bash $0 [args]" >&2
    exit 1
fi

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Script version and configuration
SCRIPT_VERSION="2.0"
SCRIPT_NAME=$(basename "$0")

# Default configuration - can be overridden by command line args
declare -A CONFIG
CONFIG["long_command_threshold"]=100        # Commands over N seconds
CONFIG["busy_threshold"]=20                # Running commands threshold
CONFIG["lock_threshold"]=10000             # Lock wait/held threshold in ms
CONFIG["output_format"]="text"             # text, json, csv, html
CONFIG["show_progress"]=true               # Show progress indicators
CONFIG["parallel_queries"]=false           # Run queries in parallel (experimental)
CONFIG["top_limit"]=25                     # Default limit for top N queries
CONFIG["report_sections"]="all"            # all, performance, locks, users, system

# Global variables
TEMP_DIR=""
DB_FILE=""
OUTPUT_FILE=""
QUIET=false

# Color codes for output
if [[ -t 1 ]]; then  # Only use colors if outputting to terminal
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m'
    readonly BLUE='\033[0;34m'
    readonly NC='\033[0m' # No Color
else
    readonly RED='' GREEN='' YELLOW='' BLUE='' NC=''
fi

# Logging functions
log_info() {
    [[ "$QUIET" == true ]] && return
    echo -e "${GREEN}[INFO]${NC} $*" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

log_progress() {
    [[ "$QUIET" == true ]] || [[ "${CONFIG[show_progress]}" == false ]] && return
    echo -e "${BLUE}[PROGRESS]${NC} $*" >&2
}

# Usage function
usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS] <database.db>

Enhanced P4D log analysis script with configurable thresholds and multiple output formats.

OPTIONS:
    -h, --help                  Show this help message
    -v, --version              Show script version
    -q, --quiet                Suppress progress messages
    -o, --output FILE          Output file (default: auto-generated)
    -f, --format FORMAT        Output format: text, json, csv, html (default: text)
    -t, --threshold TYPE=VALUE Set threshold values:
                              long_cmd=N     (commands over N seconds, default: 100)
                              busy=N         (running commands threshold, default: 20)
                              locks=N        (lock threshold in ms, default: 10000)
                              limit=N        (top N results, default: 25)
    -s, --sections SECTIONS    Report sections: all, performance, locks, users, system
                              (comma-separated, default: all)
    --parallel                 Enable parallel query execution (experimental)
    --no-progress             Disable progress indicators

EXAMPLES:
    $SCRIPT_NAME logs.db
    $SCRIPT_NAME -f json -o report.json logs.db
    $SCRIPT_NAME -t long_cmd=200 -t busy=50 logs.db
    $SCRIPT_NAME -s performance,locks logs.db

EOF
}

# Cleanup function
cleanup() {
    local exit_code=$?
    if [[ -n "$TEMP_DIR" ]] && [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
    exit $exit_code
}

# Set up cleanup trap
trap cleanup EXIT INT TERM

# Validate database file
validate_database() {
    local db_file="$1"
    
    # Check file existence
    if [[ ! -f "$db_file" ]]; then
        log_error "Database file '$db_file' not found"
        return 1
    fi
    
    # Check file readability
    if [[ ! -r "$db_file" ]]; then
        log_error "Database file '$db_file' is not readable"
        return 1
    fi
    
    # Check if it's a valid SQLite database
    if ! sqlite3 "$db_file" "SELECT 1;" &>/dev/null; then
        log_error "File '$db_file' is not a valid SQLite database"
        return 1
    fi
    
    # Check for required tables
    local required_tables=("process" "tableUse")
    for table in "${required_tables[@]}"; do
        if ! sqlite3 "$db_file" "SELECT 1 FROM $table LIMIT 1;" &>/dev/null; then
            log_error "Required table '$table' not found in database"
            return 1
        fi
    done
    
    log_info "Database validation passed"
    return 0
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--version)
                echo "$SCRIPT_NAME version $SCRIPT_VERSION"
                exit 0
                ;;
            -q|--quiet)
                QUIET=true
                shift
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -f|--format)
                CONFIG[output_format]="$2"
                shift 2
                ;;
            -t|--threshold)
                if [[ "$2" =~ ^([^=]+)=([0-9]+)$ ]]; then
                    local threshold_name="${BASH_REMATCH[1]}"
                    local threshold_value="${BASH_REMATCH[2]}"
                    case "$threshold_name" in
                        long_cmd)
                            CONFIG[long_command_threshold]="$threshold_value"
                            ;;
                        busy)
                            CONFIG[busy_threshold]="$threshold_value"
                            ;;
                        locks)
                            CONFIG[lock_threshold]="$threshold_value"
                            ;;
                        limit)
                            CONFIG[top_limit]="$threshold_value"
                            ;;
                        *)
                            log_error "Unknown threshold type: $threshold_name"
                            exit 1
                            ;;
                    esac
                else
                    log_error "Invalid threshold format. Use: TYPE=VALUE"
                    exit 1
                fi
                shift 2
                ;;
            -s|--sections)
                CONFIG[report_sections]="$2"
                shift 2
                ;;
            --parallel)
                CONFIG[parallel_queries]=true
                shift
                ;;
            --no-progress)
                CONFIG[show_progress]=false
                shift
                ;;
            --)
                shift
                break
                ;;
            -*)
                log_error "Unknown option: $1"
                exit 1
                ;;
            *)
                if [[ -z "$DB_FILE" ]]; then
                    DB_FILE="$1"
                else
                    log_error "Multiple database files specified"
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # Check if database file was provided
    if [[ -z "$DB_FILE" ]]; then
        log_error "No database file specified"
        usage
        exit 1
    fi
    
    # Validate output format
    case "${CONFIG[output_format]}" in
        text|json|csv|html) ;;
        *)
            log_error "Invalid output format: ${CONFIG[output_format]}"
            exit 1
            ;;
    esac
    
    # Set default output file if not specified
    if [[ -z "$OUTPUT_FILE" ]]; then
        local base_name=$(basename "$DB_FILE" .db)
        case "${CONFIG[output_format]}" in
            text) OUTPUT_FILE="${base_name}_report.txt" ;;
            json) OUTPUT_FILE="${base_name}_report.json" ;;
            csv) OUTPUT_FILE="${base_name}_report.csv" ;;
            html) OUTPUT_FILE="${base_name}_report.html" ;;
        esac
    fi
}

# Query definitions - organized by category
declare -A QUERIES
declare -A QUERY_TITLES

init_queries() {
    # Basic Information
    QUERY_TITLES[basic_timerange]="Start and end time for this log"
    QUERIES[basic_timerange]="SELECT MIN(starttime) as Start, MAX(starttime) as End 
    FROM process;"
    
    QUERY_TITLES[basic_command_counts]="How many commands of each type (top ${CONFIG[top_limit]})"
    QUERIES[basic_command_counts]="SELECT cmd, count(cmd) as NumCmds 
    FROM process 
    GROUP BY cmd 
    ORDER BY NumCmds DESC 
    LIMIT ${CONFIG[top_limit]};"
    
    QUERY_TITLES[basic_commands_by_user]="How many commands of each type per user"
    QUERIES[basic_commands_by_user]="SELECT cmd, count(cmd) as NumCmds, user 
    FROM process 
    GROUP BY cmd, user 
    ORDER BY NumCmds DESC 
    LIMIT 30;"
    
    # Performance Analysis
    QUERY_TITLES[perf_long_commands]="Commands over ${CONFIG[long_command_threshold]}s by endTime\\n   NOTE - Do lots of commands finish at the same time after a big command or lock?"
    QUERIES[perf_long_commands]="SELECT startTime, endTime, pid, user, cmd, args, 
           round(completedLapse) as 'lapse (s)', running 
    FROM process 
    WHERE completedLapse > ${CONFIG[long_command_threshold]} 
    ORDER BY endTime;"
    
    QUERY_TITLES[perf_busy_periods]="Busiest Running Per Minutes (> ${CONFIG[busy_threshold]})\\n    NOTE - When were the busy times?"
    QUERIES[perf_busy_periods]="SELECT substr(startTime,1,16) as Time, MAX(running) as Running 
    FROM process 
    GROUP BY Time 
    HAVING MAX(running) > ${CONFIG[busy_threshold]} 
    ORDER BY Running DESC 
    LIMIT ${CONFIG[top_limit]};"
    
    QUERY_TITLES[perf_memory_usage]="Highest memory usage commands (top ${CONFIG[top_limit]})"
    QUERIES[perf_memory_usage]="SELECT pid, user, cmd as command, app, 
           round(completedLapse, 2) as 'lapse (s)', 
           round(rpcRcv) as 'rpcReceiveWait (s)', 
           round(rpcSnd) as 'rpcSendWait (s)', 
           uCpu, sCpu, startTime, endTime, maxRss 
    FROM process 
    ORDER by maxRss DESC 
    LIMIT ${CONFIG[top_limit]};"
    
    QUERY_TITLES[perf_cpu_system]="System CPU - Top ${CONFIG[top_limit]} commands"
    QUERIES[perf_cpu_system]="SELECT pid, user, cmd, round(completedLapse, 3) as lapse, 
           round(rpcRcv, 3) as 'rpcReceiveWait (s)', 
           round(rpcSnd, 3) as 'rpcSendWait (s)', 
           uCpu as uCPU_ms, sCpu as sCPU_ms, startTime, endTime 
    FROM process 
    ORDER BY sCpu DESC 
    LIMIT ${CONFIG[top_limit]};"
    
    QUERY_TITLES[perf_cpu_user]="User CPU - Top ${CONFIG[top_limit]} commands"
    QUERIES[perf_cpu_user]="SELECT pid, user, cmd, round(completedLapse, 3) as lapse, 
           round(rpcRcv, 3) as 'rpcReceiveWait (s)', 
           round(rpcSnd, 3) as 'rpcSendWait (s)', 
           uCpu as uCPU_ms, sCpu as sCPU_ms, startTime, endTime 
    FROM process 
    ORDER BY uCpu DESC 
    LIMIT ${CONFIG[top_limit]};"
    
    QUERY_TITLES[perf_io_usage]="Consumed Most IO (top ${CONFIG[top_limit]})"
    QUERIES[perf_io_usage]="SELECT user, cmd, SUM(pagesIn+pagesOut) as ioPages, 
           process.processKey, process.args 
    FROM tableUse 
    JOIN process USING (processKey) 
    GROUP BY tableUse.processKey 
    ORDER BY ioPages DESC 
    LIMIT ${CONFIG[top_limit]};"
    
    QUERY_TITLES[perf_read_write_pct]="Read / Write Percentage - Percentage of pages read and pages written"
    QUERIES[perf_read_write_pct]="SELECT round(TOTAL(pagesIn) * 100.0 / (TOTAL(pagesIn)+TOTAL(pagesOut)), 3) as readPct, 
           round(TOTAL(pagesOut) * 100.0 / (TOTAL(pagesIn)+TOTAL(pagesOut)), 3) as writePct 
    FROM tableUse;"
    
    # Lock Analysis
    QUERY_TITLES[locks_contention_summary]="DB CONTENTION - Average Locks Summary (with total locks > ${CONFIG[lock_threshold]} ms)\\n   NOTE - Does one table have high average or total wait (victims) or held (culprits)?"
    QUERIES[locks_contention_summary]="SELECT * FROM (
        SELECT tableName, 
               COUNT(readLocks) AS NumReadLocks,
               round(AVG(readLocks)) AS 'Avg Read Locks (ms)', 
               round(AVG(writeLocks)) AS 'Avg Write Locks (ms)', 
               round(AVG(totalReadWait)) AS 'Avg totalRead Wait (ms)', 
               round(AVG(totalReadHeld)) AS 'Avg totalRead Held (ms)', 
               round(AVG(totalWriteWait)) AS 'Avg totalWrite Wait (ms)', 
               round(AVG(totalWriteHeld)) AS 'Avg totalWrite Held (ms)', 
               round(SUM(totalReadWait)+SUM(totalWriteWait)) AS 'Total Wait (ms)', 
               round(SUM(totalReadHeld)+SUM(totalWriteHeld)) AS 'Total Held (ms)' 
        FROM tableUse 
        GROUP BY tableUse.tableName
    ) 
    WHERE \"Total Wait (ms)\" > ${CONFIG[lock_threshold]} 
      AND \"Total Held (ms)\" > ${CONFIG[lock_threshold]} 
    ORDER BY \"Total Wait (ms)\" DESC;"
    
    QUERY_TITLES[locks_blocking_commands]="Blocking Commands - Commands that blocked others (top 30) - totals in ms"
    QUERIES[locks_blocking_commands]="SELECT startTime, endTime, running, user, cmd, pid, tablename,
           maxReadHeld, totalReadHeld, maxWriteHeld, totalWriteHeld, 
           totalReadWait, totalWriteWait 
    FROM tableUse 
    JOIN process USING (processKey) 
    WHERE (totalReadHeld > ${CONFIG[lock_threshold]} or totalWriteHeld > ${CONFIG[lock_threshold]}) 
      AND tablename not like 'meta%' 
      AND tablename not like 'clients%' 
      AND tablename not like 'changes%' 
    ORDER BY startTime, endTime 
    LIMIT 30;"
    
    QUERY_TITLES[locks_blocked_commands]="Blocked commands - victims of the above (top 30)"
    QUERIES[locks_blocked_commands]="SELECT startTime, endTime, computedLapse, running, user, cmd, pid, tablename, 
           maxReadHeld, maxWriteHeld, totalReadWait, totalWriteWait 
    FROM tableUse 
    JOIN process USING (processKey) 
    WHERE (totalReadWait > ${CONFIG[lock_threshold]}) 
       or (totalWriteWait > ${CONFIG[lock_threshold]}) 
    ORDER BY startTime, endTime 
    LIMIT 30;"
    
    QUERY_TITLES[locks_worst_offenders]="Worst lock offenders - Users whose commands hold locks (top ${CONFIG[top_limit]})"
    QUERIES[locks_worst_offenders]="SELECT user, 
           SUM(maxreadHeld+maxwriteHeld) as 'held (ms)' 
    FROM tableUse 
    JOIN process USING (processKey) 
    GROUP BY user 
    ORDER BY \"held (ms)\" DESC 
    LIMIT ${CONFIG[top_limit]};"
    
    QUERY_TITLES[locks_avg_wait_time]="Average wait time"
    QUERIES[locks_avg_wait_time]="SELECT ROUND(AVG(totalreadWait+totalwriteWait), 2) as wait 
    FROM tableUse;"
    
    # Compute Analysis
    QUERY_TITLES[compute_longest_phases]="Longest Compute Phases (top ${CONFIG[top_limit]}) in ms"
    QUERIES[compute_longest_phases]="SELECT process.processKey, 
           user, 
           cmd, 
           startTime, 
           CASE 
               WHEN MAX(totalreadHeld + totalwriteHeld) > MAX(totalreadWait + totalwriteWait) 
               THEN MAX(totalreadHeld + totalwriteHeld) - MAX(totalreadWait + totalwriteWait) 
               ELSE MAX(totalreadHeld + totalwriteHeld) 
           END AS compute, 
           args 
    FROM tableUse 
    JOIN process USING (processKey) 
    GROUP BY tableUse.processKey 
    ORDER BY compute DESC 
    LIMIT ${CONFIG[top_limit]};"
    
    # Replication (if applicable)
    QUERY_TITLES[repl_avg_times]="Average replication times (on master)"
    QUERIES[repl_avg_times]="SELECT substr(startTime,1,16), count(cmd), user, cmd, 
           ROUND(MAX(completedLapse), 2) AS 'Max Time', 
           ROUND(SUM(completedLapse), 2) AS 'Total Time', 
           ROUND(AVG(completedLapse), 2) AS 'Average Time', 
           COUNT(completedLapse) AS number 
    FROM process 
    WHERE cmd = 'rmt-Journal' 
    GROUP BY substr(startTime,1,16), user;"
}

# Format duration to nearest second
format_duration() {
    local duration="$1"
    
    # Round to nearest second using printf
    printf "%.0f" "$duration"
}

# Query execution with error handling
execute_query() {
    local query_name="$1"
    local query="${QUERIES[$query_name]}"
    local output_file="$2"
    
    log_progress "Executing query: $query_name"
    
    # Add query comment header like original script
    {
        # echo ""
        # Clean up query for display (preserve multi-line formatting and indentation)
        # Only remove trailing whitespace, preserve leading spaces for indentation
        local clean_query
        clean_query=$(echo "$query" | sed 's/[[:space:]]*$//')
        echo "$clean_query"
        echo ""
    } >> "$output_file"
    
    # Record start time
    local start_time=$(date +%s)
    
    # Execute the query with headers and column formatting, including pragma optimize
    local optimized_query="pragma optimize; $query"
    if ! sqlite3 -header -column "$DB_FILE" "$optimized_query" >> "$output_file" 2>/dev/null; then
        log_warn "Query '$query_name' failed or returned no results"
        echo "-- Query '$query_name' failed or returned no results" >> "$output_file"
        return 1
    fi
    
    # Calculate execution time
    local end_time=$(date +%s)
    
    # Calculate duration using bc if available, otherwise awk
    local duration
    if command -v bc >/dev/null 2>&1; then
        duration=$(echo "$end_time - $start_time" | bc -l)
    else
        duration=$(awk -v end="$end_time" -v start="$start_time" 'BEGIN {print end - start}')
    fi
    
    # Convert duration to nearest second
    local seconds=$(format_duration "$duration")
    
    # Add execution time and spacing after query results
    {
        echo ""
        echo "-- Execution time: ${seconds}s"
        echo ""
    } >> "$output_file"
    
    return 0
}

# Generate report header
generate_report_header() {
    local output_file="$1"
    
    case "${CONFIG[output_format]}" in
        text)
            {
                echo "================================================"
                echo "P4D Log Analysis Report - Enhanced Version"
                echo "================================================"
                echo "Generated: $(date)"
                echo "Database: $DB_FILE"
                echo "Script Version: $SCRIPT_VERSION"
                echo ""
                echo "Configuration:"
                echo "  Long command threshold: ${CONFIG[long_command_threshold]}s"
                echo "  Busy threshold: ${CONFIG[busy_threshold]} commands"
                echo "  Lock threshold: ${CONFIG[lock_threshold]}ms"
                echo "  Top results limit: ${CONFIG[top_limit]}"
                echo "================================================"
                echo ""
            } > "$output_file"
            ;;
        json)
            {
                echo "{"
                echo "  \"report\": {"
                echo "    \"generated\": \"$(date -Iseconds)\","
                echo "    \"database\": \"$DB_FILE\","
                echo "    \"script_version\": \"$SCRIPT_VERSION\","
                echo "    \"configuration\": {"
                echo "      \"long_command_threshold\": ${CONFIG[long_command_threshold]},"
                echo "      \"busy_threshold\": ${CONFIG[busy_threshold]},"
                echo "      \"lock_threshold\": ${CONFIG[lock_threshold]},"
                echo "      \"top_limit\": ${CONFIG[top_limit]}"
                echo "    },"
                echo "    \"sections\": {"
            } > "$output_file"
            ;;
    esac
}

# Generate report section
generate_section() {
    local section_name="$1"
    local section_title="$2"
    local queries=("${@:3}")
    local output_file="$OUTPUT_FILE"
    
    log_progress "Generating section: $section_name"
    
    case "${CONFIG[output_format]}" in
        text)
            {
                echo ""
                echo "==============================="
                echo "$section_title"
                echo "==============================="
                echo ""
            } >> "$output_file"
            
            for query_name in "${queries[@]}"; do
                if [[ -n "${QUERIES[$query_name]:-}" ]]; then
                    # Add separator and query title like original script
                    local title="${QUERY_TITLES[$query_name]:-$query_name}"
                    {
                        echo ""
                        echo "=============================="
                        echo -e "$title"
                        echo ""
                    } >> "$output_file"
                    execute_query "$query_name" "$output_file"
                fi
            done
            ;;
        json)
            echo "      \"$section_name\": {" >> "$output_file"
            local first=true
            for query_name in "${queries[@]}"; do
                if [[ -n "${QUERIES[$query_name]:-}" ]]; then
                    [[ "$first" == true ]] && first=false || echo "," >> "$output_file"
                    echo -n "        \"$query_name\": [" >> "$output_file"
                    # TODO: Implement JSON output for query results
                    echo "]" >> "$output_file"
                fi
            done
            echo "      }" >> "$output_file"
            ;;
    esac
}

# Main report generation function
generate_report() {
    log_progress "Initializing queries with current configuration..."
    init_queries
    
    log_progress "Generating report header..."
    generate_report_header "$OUTPUT_FILE"
    
    # Determine which sections to include
    local sections
    if [[ "${CONFIG[report_sections]}" == "all" ]]; then
        sections=("basic" "performance" "locks" "compute" "replication")
    else
        IFS=',' read -ra sections <<< "${CONFIG[report_sections]}"
    fi
    
    # Generate each requested section
    for section in "${sections[@]}"; do
        case "$section" in
            basic)
                generate_section "basic" "Basic Information" \
                    "basic_timerange" "basic_command_counts" "basic_commands_by_user"
                ;;
            performance)
                generate_section "performance" "Performance Analysis" \
                    "perf_long_commands" "perf_busy_periods" "perf_memory_usage" \
                    "perf_cpu_system" "perf_cpu_user" "perf_io_usage" "perf_read_write_pct"
                ;;
            locks)
                generate_section "locks" "Database Lock Analysis" \
                    "locks_contention_summary" "locks_blocking_commands" \
                    "locks_blocked_commands" "locks_worst_offenders" "locks_avg_wait_time"
                ;;
            compute)
                generate_section "compute" "Compute Analysis" \
                    "compute_longest_phases"
                ;;
            replication)
                generate_section "replication" "Replication Analysis" \
                    "repl_avg_times"
                ;;
            *)
                log_warn "Unknown section: $section"
                ;;
        esac
    done
    
    # Close JSON if needed
    if [[ "${CONFIG[output_format]}" == "json" ]]; then
        {
            echo "    }"
            echo "  }"
            echo "}"
        } >> "$OUTPUT_FILE"
    fi
}

# Main function
main() {
    log_info "Starting $SCRIPT_NAME version $SCRIPT_VERSION"
    
    # Parse command line arguments
    parse_args "$@"
    
    # Validate database
    validate_database "$DB_FILE"
    
    # Create temporary directory
    TEMP_DIR=$(mktemp -d)
    log_progress "Created temporary directory: $TEMP_DIR"
    
    log_info "Configuration:"
    log_info "  Database: $DB_FILE"
    log_info "  Output: $OUTPUT_FILE"
    log_info "  Format: ${CONFIG[output_format]}"
    log_info "  Long command threshold: ${CONFIG[long_command_threshold]}s"
    log_info "  Busy threshold: ${CONFIG[busy_threshold]} commands"
    log_info "  Lock threshold: ${CONFIG[lock_threshold]}ms"
    
    # Generate the report
    generate_report
    
    log_info "Report generated successfully: $OUTPUT_FILE"
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi