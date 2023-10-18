#!/bin/bash
# Basic log analysis via sqlite3 for log2sql
# Expects the <database>.db file to be passed in as the sole parameter

function bail () { echo "\nError: ${1:-Unknown Error}"; exit ${2:-1}; }

[[ ! -f "$1" ]] && bail "Please specify the <database>.db file as the parameter!"

dbfile="$1"

sqlinput=_sql.in
sqlreport=_sql.txt

# Initialize SQL queries to be run
# We make it an array with alternate strings: title/sql statement
# Bit of a faff to iterate over, but otherwise the order is not preserved in hash (associatve array)
title_query=(
    "Start and end time for this log"
        ".width"
        "
        SELECT MIN(starttime) as Start, MAX(starttime) as End
        FROM process;
        "

    "How many commands of each type (top 20)"
        ".width 20"
        "
        SELECT cmd, count(cmd) as NumCmds FROM process
        GROUP BY cmd
        ORDER BY NumCmds DESC LIMIT 20;
        "

    "How many commands of each type per user"
        ".width 20 0 20"
        "
        SELECT cmd, count(cmd) as NumCmds, user 
        FROM process
        GROUP BY cmd, user
        ORDER BY NumCmds DESC LIMIT 30;
        "

    "DB CONTENTION - Average Locks Summary (with total locks > 10 seconds)\\n   NOTE - Does one table have high average or total wait (victims) or held (culprits)?"
        ".width"
        "
        SELECT * FROM
        (SELECT
        tableName,
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
        GROUP BY tableUse.tableName) 
        WHERE 'Total Wait (ms)' > 10000 
        AND 'Total Held (ms)' > 10000
        ORDER BY 'Total Wait (ms)' DESC;
        "

    "Commands over 100s by endTime\\n   NOTE - Do lots of commands finish at the same time after a big command or lock?"
        ".width 0 0 0 20 20 20"
        "
        SELECT startTime, endTime, pid, user, cmd, args, round(completedLapse) as 'lapse (s)', running 
        FROM process 
        WHERE completedLapse > 100 
        ORDER BY endTime;
        "

    "Busiest Running Per Minutes (> 20)\\n    NOTE - When were the busy times?"
        ".width"
        "
        SELECT substr(startTime,1,16) as Time, MAX(running) as Running
        FROM process
        GROUP BY Time HAVING MAX(running) > 20
        ORDER BY Running DESC LIMIT 20;
        "

    "Highest memory usage commands (top 20)"
        ".width 0 20 20 40"
        "
        SELECT pid, user, cmd as command, app, round(completedLapse, 2) as 'lapse (s)', round(rpcRcv) as 'rpcReceiveWait (s)', round(rpcSnd) as 'rpcSendWait (s)', uCpu, sCpu, startTime, endTime, maxRss
        FROM process
        ORDER by maxRss DESC LIMIT 20;
        "

    "Average replication times (on master)"
        ".width"
        "
        SELECT substr(startTime,1,16), count(cmd), user, cmd, ROUND(MAX(completedLapse), 2) AS 'Max Time', ROUND(SUM(completedLapse), 2) AS 'Total Time', ROUND(AVG(completedLapse), 2) AS 'Average Time', COUNT(completedLapse) AS number 
        FROM process 
        WHERE cmd = 'rmt-Journal'
        GROUP BY substr(startTime,1,16), user;
        "

    "Average wait time"
        ".width"
        "
        SELECT ROUND(AVG(totalreadWait+totalwriteWait), 2) as wait
        FROM tableUse;
        "

    "Worst lock offenders - Users whose commands hold locks (top 25)"
        ".width 20"
        "
        SELECT user, SUM(maxreadHeld+maxwriteHeld) as 'held (ms)'
        FROM tableUse JOIN process USING (processKey)
        GROUP BY user ORDER BY 'held (ms)' DESC LIMIT 25;
        "

    "Blocking Commands - Commands that blocked others (top 30) - totals in ms"
        ".width 0 0 0 20 20 0 20"
        "
        SELECT startTime, endTime, running, user, cmd, pid, tablename,
            maxReadHeld, totalReadHeld, maxWriteHeld, totalWriteHeld, totalReadWait, totalWriteWait
        FROM tableUse JOIN process USING (processKey)
        WHERE (totalReadHeld > 10000 or totalWriteHeld > 10000)
        AND tablename not like 'meta%'
        AND tablename not like 'clients%'
        AND tablename not like 'changes%'
        ORDER BY startTime, endTime
        LIMIT 30;
        "

    "Blocking Commands including meta tables - Commands that blocked others including meta_db and clients locks (top 30) - totals in ms"
        ".width 0 0 0 20 20 0 20"
        "
        SELECT startTime, endTime, running, user, cmd, pid, tablename,
          maxReadHeld, totalReadHeld, maxWriteHeld, totalWriteHeld, totalReadWait, totalWriteWait
        FROM tableUse JOIN process USING (processKey)
        WHERE (totalReadHeld > 10000 or totalWriteHeld > 10000)
        ORDER BY startTime, endTime
        LIMIT 30;
        "

    "Blocked commands - victims of the above (top 30)"
        ".width 0 0 0 0 20 20 20"
        "
        SELECT startTime, endTime, computedLapse, running, user, cmd, pid, tablename,
          maxReadHeld, maxWriteHeld, totalReadWait, totalWriteWait
        FROM tableUse JOIN process USING (processKey)
        WHERE (totalReadWait > 10000) or (totalWriteWait > 10000)
        ORDER BY startTime, endTime
        LIMIT 30;
        "

    "Longest Compute Phases (top 25) in ms"
        ".width 0 20 20"
        "
        SELECT process.processKey, user, cmd, startTime,
        CASE WHEN MAX(totalreadHeld + totalwriteHeld) > MAX(totalreadWait + totalwriteWait) THEN
            MAX(totalreadHeld + totalwriteHeld) - MAX(totalreadWait + totalwriteWait)
        ELSE
            MAX(totalreadHeld + totalwriteHeld)
        END
        AS compute, args
        FROM tableUse JOIN process USING (processKey)
        GROUP BY tableUse.processKey
        ORDER BY compute DESC LIMIT 25;
        "

    "Consumed Most IO (top 25)"
        ".width 20 20"
        "
        SELECT user, cmd, SUM(pagesIn+pagesOut) as ioPages, process.processKey, process.args
        FROM tableUse JOIN process USING (processKey)
        GROUP BY tableUse.processKey ORDER BY ioPages
        DESC LIMIT 25;
        "

    "Read / Write Percentage - Percentage of pages read and pages written"
        ".width"
        "
        SELECT round(TOTAL(pagesIn) * 100.0 / (TOTAL(pagesIn)+TOTAL(pagesOut)), 3) as readPct,
        round(TOTAL(pagesOut) * 100.0 / (TOTAL(pagesIn)+TOTAL(pagesOut)), 3) as writePct
        FROM tableUse;
        "

    "System CPU - Top 25 commands"
        ".width 0 20 20"
        "
        SELECT pid, user, cmd, round(completedLapse, 3) as lapse, round(rpcRcv, 3) as 'rpcReceiveWait (s)', round(rpcSnd, 3) as 'rpcSendWait (s)', uCpu as uCPU_ms, sCpu as sCPU_ms, startTime, endTime
        FROM process 
        ORDER BY sCpu_ms DESC LIMIT 25;
        "

    "User CPU - Top 25 commands"
        ".width 0 20 20"
        "
        SELECT pid, process.user, process.cmd, round(completedLapse, 3) as lapse, round(rpcRcv, 3) as 'rpcReceiveWait (s)', round(rpcSnd, 3) as 'rpcSendWait (s)', uCpu as uCPU_ms, sCpu as SCPU_ms, startTime, endTime 
        FROM process 
        ORDER BY uCpu_ms DESC LIMIT 25;
        "
)

# Now populate keys array (in order) and then a hash for the queries for lookup
keys=() # In order
declare -A queries
declare -A widths

for ((i = 0; i < ${#title_query[@]}; i++))
do
    s="${title_query[$i]}"
    if [[ $((i % 3)) -eq 0 ]]; then # Process groups of 3
        k="$s"
        w=""
        keys+=("$k")
    else
        if [[ -z "$w" ]]; then
            w="$s"
            widths["$k"]="$w"
        else
            v="$s"
            queries["$k"]="$v"
        fi
    fi
done

# Create the report file with sql statements which is subsequently run

cat > $sqlinput <<EOF
.output $sqlreport
.mode column
.print "P4D Log2SQL summary report for database file: $dbfile"
EOF

# Iterate through keys in order extracting them and their corresponding query
for ((i = 0; i < ${#keys[@]}; i++))
do
    k="${keys[$i]}"
    {
        q="${queries["$k"]}"
        q="${q//[$'\t\r\n']}"   # Strip newlines
        q="${q//       }"   # Strip 7 starting spaces
        echo ".print \"\\n==============================\""
        echo ".print \"$k\\n\""
        echo ".print \"${q}\\n\""
        echo ".headers on"
        echo "${widths["$k"]}"
        echo "${queries["$k"]}"
        echo ".headers off"
        echo ".print  \"\""
        echo "SELECT 'Date run: ' || strftime('%Y-%m-%d %H:%M:%S', datetime('now'));"
    } >> $sqlinput
done

sqlite3 "$dbfile" < $sqlinput

cat $sqlreport

echo "Output has been saved in: $sqlreport"
