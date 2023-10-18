#!/bin/bash
# Basic log analysis via sqlite3 for log2sql
# Expects the <database>.db file to be passed in as the sole parameter

function bail () { echo "\nError: ${1:-Unknown Error}"; exit ${2:-1}; }

[[ ! -f "$1" ]] && bail "Please specify the <database>.db file as the parameter!"

sqlinput=_sql.in
sqlreport=_sql.txt

# Initialize SQL queries to be run
# We make it an array with alternate strings: title/sql statement
# Bit of a faff to iterate over, but otherwise the order is not preserved in hash (associatve array)
title_query=(
    "Start and end time for this log"
        ".width"
        "
        select MIN(starttime) as Start, MAX(starttime) as End
        from process;
        "

    "How many commands of each type (top 20)"
        ".width 20"
        "
        select cmd, count(cmd) as CountCmds from process
        group by cmd
        order by CountCmds desc limit 20;
        "

    "How many commands of each type per user"
        ".width 20 0 20"
        "
        select cmd, count(cmd) as CountCmds, user 
        from process
        group by cmd, user
        order by CountCmds desc limit 30;
        "

    "DB CONTENTION - Average Locks Summary (with total locks > 10 seconds)\\n   NOTE - Does one table have high average or total wait (victims) or held (culprits)?"
        ".width"
        "
        select * FROM
        (select
            tableName,
            COUNT(readLocks) AS Number,
            round(AVG(readLocks))  AS 'Avg Read Locks (ms)',
            round(AVG(writeLocks))  AS 'Avg Write Locks (ms)',
            round(AVG(totalReadWait))  AS 'Avg totalRead Wait (ms)',
            round(AVG(totalReadHeld))  AS 'Avg totalRead Held (ms)',
            round(AVG(totalWriteWait))  AS 'Avg totalWrite Wait (ms)',
            round(AVG(totalWriteHeld))  AS 'Avg totalWrite Held (ms)',
            round(SUM(totalReadWait)+SUM(totalWriteWait)) AS 'Total Wait (ms)',
            round(SUM(totalReadHeld)+SUM(totalWriteHeld)) AS 'Total Held (ms)'
        FROM tableUse
        GROUP BY tableUse.tableName) 
        WHERE 
            'Total Wait (ms)' > 10000 
            AND 'Total Held (ms)' > 10000 ORDER BY 'Total Wait (ms)' DESC;
        "

    "Commands over 100s by endTime\\n   NOTE - Do lots of commands finish at the same time after a big command or lock?"
        ".width 0 0 0 20 20 20"
        "
        select startTime, endTime, pid, user, cmd, args, completedLapse, running 
        from process 
        where completedLapse > 100 
        order by endTime;
        "

    "Busiest Running Per Minutes\\n    NOTE - When were the busy times?"
        ".width"
        "
        select substr(startTime,1,16) as Time, MAX(running) as Running
        from process
        group by Time HAVING MAX(running) > 20
        order by Running desc limit 20;
        "

    "Highest memory usage commands (top 20)"
        ".width 0 20 20 40"
        "
        SELECT pid, user, cmd as command, app, round(completedLapse) as 'lapse (s)', round(rpcRcv) as 'rpcReceiveWait (s)', round(rpcSnd) as 'rpcSendWait (s)', uCpu, sCpu, startTime, endTime, maxRss
        FROM process
        ORDER by maxRss DESC LIMIT 20;
        "

    "Average replication times (on master)"
        ".width"
        "
        SELECT substr(startTime,1,16), count(cmd), user, cmd, ROUND(MAX(completedLapse)) AS 'Max Time', ROUND(SUM(completedLapse)) AS 'Total Time', ROUND(AVG(completedLapse)) AS 'Average Time', COUNT(completedLapse) AS number 
        from process 
        WHERE cmd = 'rmt-Journal'
        group by substr(startTime,1,16), user;
        "

    "Average wait time"
        ".width"
        "
        SELECT AVG(totalreadWait+totalwriteWait) as wait
        FROM tableUse;
        "

    "Worst lock offenders - Users whose commands hold locks (top 25)"
        ".width 20"
        "
        SELECT user, SUM(maxreadHeld+maxwriteHeld) as 'held (ms)'
        FROM tableUse JOIN process USING (processKey)
        GROUP BY user ORDER BY 'held {ms)' DESC LIMIT 25;
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
            limit 30;
        "

    "Blocking Commands including meta tables - Commands that blocked others including meta_db and clients locks (top 30) - totals in ms"
        ".width 0 0 0 20 20 0 20"
        "
        SELECT startTime, endTime, running, user, cmd, pid, tablename,
            maxReadHeld, totalReadHeld, maxWriteHeld, totalWriteHeld, totalReadWait, totalWriteWait
        FROM tableUse JOIN process USING (processKey)
        WHERE (totalReadHeld > 10000 or totalWriteHeld > 10000)
        ORDER BY startTime, endTime
            limit 30;
        "

    "Blocked commands - victims of the above (top 30)"
        ".width 0 0 0 0 20 20 20"
        "
        SELECT startTime, endTime, computedLapse, running, user, cmd, pid, tablename,
            maxReadHeld, maxWriteHeld, totalReadWait, totalWriteWait
        FROM tableUse JOIN process USING (processKey)
        WHERE (totalReadWait > 10000) or (totalWriteWait > 10000)
        ORDER BY startTime, endTime
        limit 30;
        "

    "Longest Compute Phases (top 25)"
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
        select pid, user, cmd, round(completedLapse, 3) as lapse, rpcRcv, rpcSnd, uCpu as uCPU_ms, sCpu as sCPU_ms, startTime, endTime
        from process 
        order by sCpu_ms desc limit 25;
        "

    "User CPU - Top 25 commands"
        ".width 0 20 20"
        "
        select pid, process.user, process.cmd, round(completedLapse, 3) as lapse, rpcRcv, rpcSnd, uCpu as uCPU_ms, sCpu as SCPU_ms, startTime, endTime 
        from process 
        order by uCpu_ms desc limit 25;
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
EOF

# Iterate through keys in order extracting them and their corresponding query
for ((i = 0; i < ${#keys[@]}; i++))
do
    k="${keys[$i]}"
    {
        q="${queries["$k"]}"
        q="${q//[$'\t\r\n']}"   # Strip newlines
        q="${q//        }"   # Strip starting spaces
        echo ".print \"\\n==============================\""
        echo ".print \"$k\\n\""
        echo ".print \"${q}\\n\""
        echo ".headers on"
        echo "${widths["$k"]}"
        echo "${queries["$k"]}"
        echo ".headers off"
        echo ".print  \"\""
        echo "select 'Date run: ' || strftime('%Y-%m-%d %H:%M:%S', datetime('now'));"
    } >> $sqlinput
done

sqlite3 $1 < $sqlinput

cat $sqlreport
