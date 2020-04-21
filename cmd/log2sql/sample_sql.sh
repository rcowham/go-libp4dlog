#!/bin/bash
# Sample SQL reports from LOG2SQL database

function bail () { echo "\nError: ${1:-Unknown Error}\n"; exit ${2:-1}; }

# Runs SQL report for specified run
dbfile=${1:-Unset}
[[ $dbfile == "Unset" ]] && bail "Specify dbfile.db as (single) parameter to this script"

sqlreport=sql.txt

echo "Writing report to $sqlreport"

cat > sql.in <<EOF
.output $sqlreport

.mode column

.print "Start and end time for this log\n"

select MIN(starttime) as Start, MAX(starttime) as End
from process;

.print "\n"
.print "How many commands of each type\n"

select cmd, count(cmd) as CountCmds from process
group by cmd
order by CountCmds desc limit 20;


.print "\n"
.print "How many commands of each type per user\n"

select cmd, count(cmd) as CountCmds, user 
from process
group by cmd, user
order by CountCmds desc limit 30;

.print "\n"
.print "Cmd averages"

select cmd, count(cmd), 
round(cast(avg(completedLapse) AS DECIMAL(9, 3)), 3) as "Avg Time", 
round(cast(max(completedLapse) AS DECIMAL(9, 3)), 3) as "Max Time",
round(cast(sum(completedLapse) AS DECIMAL(9, 3)), 3) as "Sum Time"
from process
group by cmd;

.print "\n"

/*
NOTE - in the following, width is required to avoid chopping columns.
See also the figures are divided by 200 - play with this value depending on size of your data.
*/

.width 18 5 200

.print "Submits per 10 seconds\n"
select substr(starttime, 1, 15) as time, count(cmd) as cmds,
replace(substr(quote(zeroblob(COUNT(cmd) / 200)), 3, COUNT(cmd)), '0', '*') AS bar
from process
group by time;
.print "\n"

/*

{'title': 'Average wait time',
    SELECT AVG(totalreadWait+totalwriteWait) as wait
    FROM tableUse;

{'title': 'Worst lock offenders',
    SELECT user, SUM(maxreadHeld+maxwriteHeld) as held
    FROM tableUse JOIN process USING (processKey)
    GROUP BY user ORDER BY held DESC LIMIT 25;

{'title': 'Blocking Commands',
    SELECT startTime, endTime, running, user, cmd, pid, tablename,
        maxReadHeld, maxWriteHeld, totalReadWait, totalWriteWait
    FROM tableUse JOIN process USING (processKey)
    WHERE (totalReadHeld > 10000 or totalWriteHeld > 10000)
        AND tablename not like 'meta%'
        AND tablename not like 'clients%'
        AND tablename not like 'changes%'
    ORDER BY startTime, endTime
        limit 30;

{'title': 'Blocking Commands including meta tables',
    SELECT startTime, endTime, running, user, cmd, pid, tablename,
        maxReadHeld, maxWriteHeld, totalReadWait, totalWriteWait
    FROM tableUse JOIN process USING (processKey)
    WHERE (totalReadHeld > 10000 or totalWriteHeld > 10000)
    ORDER BY startTime, endTime
        limit 30;

{'title': 'Block commands - victims of the above',
    SELECT startTime, endTime, computedLapse, running, user, cmd, pid, tablename,
        maxReadHeld, maxWriteHeld,totalReadWait, totalWriteWait
    FROM tableUse JOIN process USING (processKey)
    WHERE (totalReadWait > 10000) or (totalWriteWait > 10000)
    ORDER BY startTime, endTime
    limit 30;

{'title': 'Longest Compute Phases',
    SELECT process.processKey, user, cmd, args, startTime,
    CASE WHEN MAX(totalreadHeld + totalwriteHeld) > MAX(totalreadWait + totalwriteWait) THEN
        MAX(totalreadHeld + totalwriteHeld) - MAX(totalreadWait + totalwriteWait)
    ELSE
        MAX(totalreadHeld + totalwriteHeld)
    END
    AS compute
    FROM tableUse JOIN process USING (processKey)
    GROUP BY tableUse.processKey
    ORDER BY compute DESC LIMIT 25

{'title': 'Consumed Most IO',
    SELECT user, cmd, SUM(pagesIn+pagesOut) as io, process.processKey, process.args
    FROM tableUse JOIN process USING (processKey)
    GROUP BY tableUse.processKey ORDER BY io
    DESC LIMIT 25

{'title': 'Read / Write Percentage',
    SELECT TOTAL(pagesIn) * 100.0 / (TOTAL(pagesIn)+TOTAL(pagesOut)) as readPct,
        TOTAL(pagesOut) * 100.0 / (TOTAL(pagesIn)+TOTAL(pagesOut)) as writePct
    FROM tableUse

{'title': 'Top 25 commands by system CPU',
    select pid, user, cmd, completedLapse, rpcRcv, rpcSnd, uCpu, sCpu, startTime, endTime
    from process 
    order by sCpu desc limit 25

{'title': 'User CPU',
'explanation': 'Top 25 commands by user CPU',
'sql': """
    select pid, user, cmd, completedLapse, rpcRcv, rpcSnd, uCpu, sCpu, startTime, endTime 
    from process 
    order by uCpu desc limit 25 

*/
/*

.print "\n"
.print "Submit  times\n"
select substr(workspace, 7, 12) as svr, min(substr(starttime, 12, 8)) as 'start', 
  max(substr(endtime, 12, 8)) as 'end', count(completedlapse) as 'count' 
from process where cmd = "user-submit" 
group by svr;

.print "\n"
.print "Sync times\n"
select substr(workspace, 7, 12) as svr, min(substr(starttime, 12, 8)) as 'start', 
  max(substr(endtime, 12, 8)) as 'end', count(completedlapse) as 'count'
from process where cmd = "user-sync" or cmd = "cmd-transmit" and completedlapse > 1
group by svr;

PRAGMA temp_store = 2;      -- store temp table in memory, not on disk
CREATE TEMP TABLE _Variables(Start DATE, SubmitStart DATE, SubmitEnd DATE);

.print "\n"
insert into _variables
values((select min(starttime) from process where cmd = "user-sync" or cmd = "user-transmit"),
    (select min(starttime) from process where cmd = "user-submit"),
    (select max(endtime) from process where cmd = "user-submit"));

select CAST ((julianday(SubmitStart) - julianday(start)) * 24 * 60 * 60 as INTEGER) as Phase1Duration,
    CAST ((julianday(SubmitEnd) - julianday(SubmitStart)) * 24 * 60 * 60 as INTEGER) as Phase2Duration
from _variables;

.print "\n"

select CAST ((julianday(max(endtime)) - julianday(min(starttime))) * 24 * 60 * 60 as INTEGER) as TotalSecondsDuration 
from process where cmd = 'user-sync' or cmd = 'user-transmit';
*/

.print "\n"

EOF

echo "Executing SQL statements"

sqlite3 -header "$dbfile" < sql.in

cat $sqlreport
