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
        "
        select MIN(starttime) as Start, MAX(starttime) as End
        from process;
        "

    "How many commands of each type (top 20)"
        "
        select cmd, count(cmd) as CountCmds from process
        group by cmd
        order by CountCmds desc limit 20;
        "

    "How many commands of each type per user"
        "
        select cmd, count(cmd) as CountCmds, user 
        from process
        group by cmd, user
        order by CountCmds desc limit 30;
        "

    "Average wait time"
        "
        SELECT AVG(totalreadWait+totalwriteWait) as wait
        FROM tableUse;
        "

    "Worst lock offenders - Users whose commands hold locks (top 25)"
        "
        SELECT user, SUM(maxreadHeld+maxwriteHeld) as held
        FROM tableUse JOIN process USING (processKey)
        GROUP BY user ORDER BY held DESC LIMIT 25;
        "

    "Blocking Commands - Commands that blocked others (top 30)"
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

    "Blocking Commands including meta tables - Commands that blocked others including meta_db and clients locks (top 30)"
        "
        SELECT startTime, endTime, running, user, cmd, pid, tablename,
            maxReadHeld, totalReadHeld, maxWriteHeld, totalWriteHeld, totalReadWait, totalWriteWait
        FROM tableUse JOIN process USING (processKey)
        WHERE (totalReadHeld > 10000 or totalWriteHeld > 10000)
        ORDER BY startTime, endTime
            limit 30;
        "

    "Blocked commands - victims of the above (top 30)"
        "
        SELECT startTime, endTime, computedLapse, running, user, cmd, pid, tablename,
            maxReadHeld, maxWriteHeld, totalReadWait, totalWriteWait
        FROM tableUse JOIN process USING (processKey)
        WHERE (totalReadWait > 10000) or (totalWriteWait > 10000)
        ORDER BY startTime, endTime
        limit 30;
        "

    "Longest Compute Phases (top 25)"
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
        "
        SELECT user, cmd, SUM(pagesIn+pagesOut) as io, process.processKey, process.args
        FROM tableUse JOIN process USING (processKey)
        GROUP BY tableUse.processKey ORDER BY io
        DESC LIMIT 25;
        "

    "Read / Write Percentage - Percentage of pages read and pages written"
        "
        SELECT TOTAL(pagesIn) * 100.0 / (TOTAL(pagesIn)+TOTAL(pagesOut)) as readPct,
            TOTAL(pagesOut) * 100.0 / (TOTAL(pagesIn)+TOTAL(pagesOut)) as writePct
        FROM tableUse;
        "

    "System CPU - Top 25 commands"
        "
        select pid, user, cmd, completedLapse, rpcRcv, rpcSnd, uCpu, sCpu, startTime, endTime
        from process 
        order by sCpu desc limit 25;
        "

    "User CPU - Top 25 commands"
        "
        select pid, user, cmd, completedLapse, rpcRcv, rpcSnd, uCpu, sCpu, startTime, endTime 
        from process 
        order by uCpu desc limit 25;
        "
)

# Now populate keys array (in order) and then a hash for the queries for lookup
keys=() # In order
declare -A queries

for ((i = 0; i < ${#title_query[@]}; i++))
do
    s="${title_query[$i]}"
    if [[ $((i%2)) -eq 0 ]]; then
        k="$s"
        keys+=("$k")
    else
        v="$s"
        queries["$k"]="$v"
    fi
done

# Create the report file with sql statements which is subsequently run

cat > $sqlinput <<EOF
.output $sqlreport
.mode column
EOF

# .width 0 0 0 0

# Iterate through keys in order extracting them and their corresponding query
for ((i = 0; i < ${#keys[@]}; i++))
do
    k="${keys[$i]}"
    {
        echo ".print \"\\n$k\\n\""
        echo ".headers on"
        echo "${queries["$k"]}"
        echo ".headers off"
        echo "select 'Date run: ' || date('now') || ' ' || time('now');"
    } >> $sqlinput
done

sqlite3 $1 < $sqlinput

cat $sqlreport
