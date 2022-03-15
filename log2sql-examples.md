# log2sql example SQL statements

These are examples of queries that might be interesting to run against
a database created by the log2sql scripts.

`log2sql` automatically creates a Sqlite3 database from a log which can be reported on via these SQL queries.

You need to install sqlite3 to be able to view (with apt-get/yum as appropriate on Linux).

Once installed, you can quickly view some results with commands like this:

```
sqlite3 -header run.db <<EOF
.mode column
SELECT cmd, count(cmd) as num_cmds
FROM process 
ORDER by num_cmds;
EOF
```

Please note, in the SQL statements below, there are sometimes 2 versions - this is because
Sqlite syntax needs "SUBSTR" not "SUBSTRING" (used by mysql and other DBMSs).

- [log2sql example SQL statements](#log2sql-example-sql-statements)
- [Locks Held for 10 seconds](#locks-held-for-10-seconds)
- [Commands waiting for locks for over 30 seconds](#commands-waiting-for-locks-for-over-30-seconds)
- [Commands running per second (look for bottlenecks)](#commands-running-per-second-look-for-bottlenecks)
- [25 Longest computes](#25-longest-computes)
- [Consumed Most I/O Not working](#consumed-most-io-not-working)
- [Average wait time](#average-wait-time)
- [Read/write percentage](#readwrite-percentage)
- [Worst lock offenders](#worst-lock-offenders)
- [Blocking Commands](#blocking-commands)
- [Block commands - victims of the above](#block-commands---victims-of-the-above)
- [Blocked and blocking locks](#blocked-and-blocking-locks)
- [Max running per second](#max-running-per-second)
- [Individual blocked commands](#individual-blocked-commands)
- [Individual commands that blocked](#individual-commands-that-blocked)
- [Looking for long locks](#looking-for-long-locks)
- [Looking for high memory footprint](#looking-for-high-memory-footprint)
- [Extract section of log](#extract-section-of-log)
- [Print a line in a file](#print-a-line-in-a-file)
- [Delete a line from a file](#delete-a-line-from-a-file)
- [VI regex for locked table (@r to run db.rev)](#vi-regex-for-locked-table-r-to-run-dbrev)
	- [Note: To record a macro:](#note-to-record-a-macro)
- [Job slow downs](#job-slow-downs)
- [Max running per second](#max-running-per-second-1)
- [Blocking Commands](#blocking-commands-1)
- [Blocked Commands](#blocked-commands)
- [Blocked and blocking locks](#blocked-and-blocking-locks-1)
- [Locks on db.rev between two times (for any date)](#locks-on-dbrev-between-two-times-for-any-date)
- [Count commands between 2 time](#count-commands-between-2-time)
- [Reported Lapse > 0](#reported-lapse--0)
- [Long lapse per hour:](#long-lapse-per-hour)
- [Average lapse per minute](#average-lapse-per-minute)
- [Incoming Commands per minute](#incoming-commands-per-minute)
- [Incoming commands per hour](#incoming-commands-per-hour)
- [Incoming Commands per user per minute](#incoming-commands-per-user-per-minute)
- [Sync commands per 10 mins](#sync-commands-per-10-mins)
- [All locks taken on a table](#all-locks-taken-on-a-table)
- [Individual locks taken on table between two times:](#individual-locks-taken-on-table-between-two-times)
- [Commands that were still running when server crashed](#commands-that-were-still-running-when-server-crashed)
- [Commands at point in time with errors](#commands-at-point-in-time-with-errors)
- [Commands per user](#commands-per-user)
- [Commands per user per 10 mins](#commands-per-user-per-10-mins)
- [Held Locks for a period of time](#held-locks-for-a-period-of-time)
- [ADDITIONAL...](#additional)
- [INTO CSV FILE - concurrent commands](#into-csv-file---concurrent-commands)
- [INTO CSV FILE - incoming commands](#into-csv-file---incoming-commands)
- [Individual blocked commands](#individual-blocked-commands-1)
- [Individual commands that blocked](#individual-commands-that-blocked-1)
- [Individual commands that blocked with MAX table held times and Lapse](#individual-commands-that-blocked-with-max-table-held-times-and-lapse)
- [Commands per application](#commands-per-application)
- [Commands per application excluding sync and submit](#commands-per-application-excluding-sync-and-submit)
- [Commands per user](#commands-per-user-1)
- [Examples of analysing benchmark script runs](#examples-of-analysing-benchmark-script-runs)

# Locks Held for 10 seconds

	SELECT startTime, endTime, computedLapse, running, 
	  cmd, pid, tablename, maxReadHeld, 
	  maxWriteHeld, totalReadWait, totalWriteWait 
	FROM tableUse JOIN process USING (processKey)
	WHERE (( totalReadHeld > 10000 or totalWriteHeld > 10000 )) 
	ORDER BY startTime, endTime;

# Commands waiting for locks for over 30 seconds

	SELECT startTime, endTime, computedLapse, running, 
	  cmd, pid, tablename, maxReadHeld,
	  maxWriteHeld, totalReadWait, totalWriteWait 
	FROM tableUse JOIN process USING (processKey)
	WHERE (( totalReadWait > 30000 or totalWriteWait > 30000 )) 
	ORDER BY startTime,endTime;

# Commands running per second (look for bottlenecks)

	SELECT SUBSTRING(startTime,1,19), MAX(running) 
	FROM process 
	GROUP BY SUBSTRING(startTime,1,19);

	SELECT SUBSTR(startTime,1,19), MAX(running) 
	FROM process 
	GROUP BY SUBSTR(startTime,1,19);

# 25 Longest computes

	SELECT
	  process.processKey,user,cmd,
	  startTime AS time,
	  MAX(maxreadHeld+maxwriteHeld)-MAX(maxreadWait+maxwriteWait)
	  AS compute
	 FROM tableUse JOIN process USING (processKey)
	 GROUP BY tableUse.processKey
	 ORDER BY compute DESC LIMIT 25;

# Consumed Most I/O Not working

	SELECT
	  user, cmd, SUM(pagesIn+pagesOut) as io
	  FROM tableUse JOIN process USING (processKey)
	  GROUP BY tableUse.processKey ORDER BY io
	  DESC LIMIT 25;

# Average wait time

	SELECT
	  AVG(totalreadWait+totalwriteWait) as wait
	  FROM tableUse;

# Read/write percentage

	SELECT
	  SUM(pagesIn)/SUM(pagesIn+pagesOut) as readPct,
	  SUM(pagesOut)/SUM(pagesIn+pagesOut) as writePct
	  FROM tableUse;

# Worst lock offenders

	 SELECT
	  user, SUM(maxreadHeld+maxwriteHeld) as held
	  FROM tableUse JOIN process USING (processKey)
	  GROUP BY user ORDER BY held DESC LIMIT 25;

# Blocking Commands

	SELECT startTime, endTime, running, cmd, pid,
		tablename, maxReadHeld,
		maxWriteHeld, totalReadWait, totalWriteWait 
	FROM tableUse JOIN process USING (processKey)
	WHERE processkey = processkey AND (( totalReadHeld > 10000 or
		totalWriteHeld > 10000 )) ORDER BY startTime, endTime;

# Block commands - victims of the above

	SELECT startTime, endTime, computedLapse, running, cmd, pid,
	tablename, maxReadHeld,
	maxWriteHeld,totalReadWait, totalWriteWait 
	FROM tableUse JOIN process USING (processKey)
	WHERE processkey = processkey AND (( totalReadWait > 10000 or
	totalWriteWait > 10000 )) 
	ORDER BY startTime, endTime;

# Blocked and blocking locks

	SELECT startTime, endTime, running, cmd, pid,
	tablename, maxReadHeld,
	maxWriteHeld,totalReadWait,totalWriteWait 
	FROM tableUse JOIN process USING (processKey)
	WHERE processkey = processkey AND (( totalReadHeld > 10000 or
	totalWriteHeld > 10000 ) or (totalReadWait > 10000 or
	totalWriteWait > 10000)) ORDER BY startTime, endTime;

# Max running per second

	SELECT SUBSTRING(startTime,1,19), MAX(running) 
	from process group by
		SUBSTRING(startTime,1,19) HAVING MAX(running) > 20 ;

	SELECT SUBSTR(startTime,1,19), MAX(running) 
	from process group by
		SUBSTR(startTime,1,19) HAVING MAX(running) > 20 ;

# Individual blocked commands

	SELECT startTime, endTime, computedLapse, running, cmd, pid,
		tablename, MAX(maxReadWait), MAX(maxWriteWait) 
	FROM tableUse JOIN process USING (processKey)
	WHERE processkey = processkey AND (( totalReadWait >
	30000 or totalWriteWait > 30000 )) GROUP BY pid 
	ORDER BY startTime, endTime;


# Individual commands that blocked

	SELECT startTime, endTime, running, cmd, pid,
		MAX(maxReadHeld),
		MAX(maxWriteHeld), MAX(maxReadWait), MAX(maxWriteWait) 
	FROM tableUse JOIN process USING (processKey)
	WHERE processkey = processkey AND (( totalReadHeld >
	30000 or totalWriteHeld > 30000 )) 
	GROUP BY pid 
	ORDER BY startTime, endTime;

# Looking for long locks

	grep -n -C10 -E "+[0-9]{6,}ms\/" p4d.log > culprits.read
	grep -n -C10 -E "+[0-9]{6,}ms" p4d.log > culprits.write

# Looking for high memory footprint

	grep -A4 -B1  'usage .* [0-9]\{8,\}k ' Smartphone_server_log_20150331.txt

# Extract section of log

	sed -n '/ 07:23:49/,/ 11:21:13/p' log-20110401 > shortlog.txt

# Print a line in a file

	sed -n 3p tst.txt

# Delete a line from a file

	sed '3d' tst.txt

# VI regex for locked table (@r to run db.rev)

	/db.revdx\n.*+[0-9][0-9][0-9][0-9][0-9]*ms
	?db.rev\n.*+[0-9][0-9][0-9][0-9]*ms

	/db.have\n.*+[0-9][0-9][0-9][0-9]*ms

	/db.locks\n.*+[0-9][0-9][0-9][0-9]*ms

	/db.resolve\n.*+[0-9][0-9][0-9][0-9]*ms

## Note: To record a macro:

	q<register><search string>q

For example:

	qr<ESC-KEY>/db.rev\n.*+[0-9][0-9][0-9][0-9]*ms<ENTER-KEY>q

would record macro into register a so you can run by typing "@a"

# Job slow downs

	SELECT SUBSTRING(startTime,1,19),cmd,args,MAX(completedLapse)
	from process 
	where cmd = 'user-job' and args = '-o' 
	group by SUBSTRING(startTime,1,19) 
	HAVING MAX(completedLapse) > 5;

	SELECT SUBSTR(startTime,1,19),cmd,args,MAX(completedLapse)
	from process 
	where cmd = 'user-job' and args = '-o' 
	group by SUBSTR(startTime,1,19) 
	HAVING MAX(completedLapse) > 5;

	SELECT SUBSTR(startTime,1,19),cmd,args,MAX(completedLapse) 
	from process 
	where cmd = 'user-job' and args = '-o' 
	group by SUBSTR(startTime,1,19) HAVING MAX(completedLapse) > 5;

	SELECT SUBSTR(startTime,1,19), cmd, args, MAX(completedLapse) 
	from process 
	where cmd = 'user-job' and args = '-o' 
	group by SUBSTR(startTime,1,19) HAVING MAX(completedLapse) > 5;

# Max running per second

	SELECT SUBSTRING(startTime,1,19),MAX(running) 
	from process group by SUBSTRING(startTime,1,19) HAVING MAX(running) > 20 ;

	SELECT SUBSTR(startTime,1,19),MAX(running) 
	from process group by SUBSTR(startTime,1,19) HAVING MAX(running) > 20 ;

	SELECT SUBSTR(startTime,1,19),MAX(running) 
	from process group by SUBSTR(startTime,1,19) HAVING MAX(running) > 20 ;

	SELECT SUBSTR(startTime,1,19),MAX(running) 
	from process group by SUBSTR(startTime,1,19) HAVING MAX(running) > 20 ;

# Blocking Commands

	SELECT p.startTime, p.endTime, p.lineNumber, p.running, p.cmd, p.pid, 
	t.tablename, t.totalReadHeld as r_R_held, t.totalWriteHeld as t_Wr_held, t.totalReadWait as t_R_wait,
	t.totalWriteWait as t_W_wait
	FROM process p, tableUse t WHERE p.processkey = t.processkey AND 
	(( t.totalReadHeld > 100000 or t.totalWriteHeld > 100000 )) 
	ORDER BY p.startTime, p.endTime,p.processkey;

# Blocked Commands

	SELECT p.startTime, p.endTime, p.computedLapse, p.running, p.cmd, p.pid, t.tablename, t.totalReadHeld, 
	t.totalWriteHeld,t.totalReadWait,t.totalWriteWait 
	FROM process p, tableUse t 
	WHERE p.processkey = t.processkey AND 
	(( t.totalReadWait > 50000 or t.totalWriteWait > 50000 ))
	ORDER BY p.startTime, p.endTime;

# Blocked and blocking locks

	SELECT p.startTime, p.endTime, p.linenumber, p.running, p.cmd, p.pid, t.tablename, t.maxReadHeld, t.maxWriteHeld,t.totalReadWait,t.totalWriteWait
	FROM process p, tableUse t WHERE p.processkey = t.processkey AND (( t.totalReadHeld > 10000 or t.totalWriteHeld > 10000 ) or (t.totalReadWait > 10000 or t.totalWriteWait > 10000)) ORDER BY p.startTime, p.endTime;

# Locks on db.rev between two times (for any date)

	SELECT startTime, p.cmd, count(cmd), SUM(t.totalReadHeld), AVG(t.totalReadHeld) 
	from process p, tableUse t 
	WHERE  p.processkey = t.processkey AND tablename = "locks" AND 
	(DATE_FORMAT(startTime, '%H:%i:%s') BETWEEN '13:42:00' AND '14:30:00') 
	GROUP BY p.cmd;

# Count commands between 2 time

	SELECT startTime,count(*)
	FROM CALL00091785_JUl23.process p 
	WHERE  (DATE_FORMAT(startTime,'%H:%i:%s') BETWEEN '08:00:00' AND '18:00:00');

# Reported Lapse > 0

	SELECT startTime, completedLapse,cmd,user,pid 
	FROM process WHERE completedLapse > 0 and cmd <> "user-sync";

# Long lapse per hour:

	SELECT SUBSTRING(startTime,1,14), COUNT(cmd),MAX(completedLapse) 
	FROM process 
	WHERE (completedLapse > 0 and cmd <> "user-sync") 
	GROUP BY SUBSTRING(startTime,1,17);

	SELECT SUBSTR(startTime,1,14), COUNT(cmd),MAX(completedLapse) 
	FROM process 
	WHERE (completedLapse > 0 and cmd <> "user-sync") 
	GROUP BY SUBSTR(startTime,1,17);

# Average lapse per minute

	SELECT SUBSTRING(startTime,1,17), COUNT(cmd), AVG(completedLapse) 
	FROM process 
	WHERE (completedLapse > 0 and cmd <> "user-sync") 
	GROUP BY SUBSTRING(startTime,1,17);

	SELECT SUBSTR(startTime,1,17), COUNT(cmd), AVG(completedLapse) 
	FROM process 
	WHERE (completedLapse > 0 and cmd <> "user-sync") 
	GROUP BY SUBSTR(startTime,1,17);

# Incoming Commands per minute

	SELECT SUBSTRING(startTime,1,17), count(user) 
	FROM process 
	group by SUBSTRING(startTime,1,17) 
	order by SUBSTRING(startTime,1,17);

	SELECT SUBSTR(startTime,1,17), count(user) 
	FROM process 
	group by SUBSTR(startTime,1,17) 
	order by SUBSTR(startTime,1,17);

# Incoming commands per hour

	SELECT SUBSTRING(startTime,1,13), count(user)
	FROM process group by SUBSTRING(startTime,1,13) order by SUBSTRING(startTime,1,13);

	SELECT SUBSTR(startTime,1,13), count(user)
	FROM process group by SUBSTR(startTime,1,13) order by SUBSTR(startTime,1,13);

# Incoming Commands per user per minute

	SELECT SUBSTRING(startTime,1,17), user, count(user)
	FROM process 
	where startTime > ' 2014-01-28 15:40:00' and 
	endTime < '2014-01-28 15:55:00' and user like 'sys%' 
	group by SUBSTRING(startTime,1,17), user 
	order by SUBSTRING(startTime,1,17),user;

	SELECT SUBSTR(startTime,1,17), user, count(user)
	FROM process
	where startTime > ' 2014-01-28 15:40:00' 
	and endTime < '2014-01-28 15:55:00' and user like 'sys%' 
	group by SUBSTR(startTime,1,17), user 
	order by SUBSTR(startTime,1,17),user;

# Sync commands per 10 mins

	SELECT SUBSTRING(startTime,1,15), user, count(user)
	FROM process WHERE cmd="user-sync" group by SUBSTRING(startTime,1,15), 
	user order by SUBSTRING(startTime,1,17),user;

	SELECT SUBSTR(startTime,1,15), user, count(user)
	FROM process WHERE cmd="user-sync" group by SUBSTR(startTime,1,15), user 
	order by SUBSTR(startTime,1,17),user;

	SELECT SUBSTR(startTime,1,15), user, count(user)
	FROM process WHERE cmd="user-sync" group by SUBSTR(startTime,1,15), user 
	order by SUBSTR(startTime,1,17),user;

# All locks taken on a table

	SELECT p.startTime, p.endTime, p.lineNumber, p.running, p.cmd, p.pid, t.tablename, t.totalReadHeld, t.totalWriteHeld
	FROM process p, tableUse t 
	WHERE p.processkey = t.processkey AND (( t.totalReadHeld > 1 or t.totalWriteHeld > 1 ) AND t.tablename = "revdx") 
	ORDER BY p.startTime, p.endTime,p.processkey;

# Individual locks taken on table between two times:

	SELECT p.startTime, p.endTime, p.user, p.cmd, p.pid, p.lineNumber, t.tablename, t.totalReadHeld, t.totalWriteHeld
	FROM process p, tableUse t 
	WHERE p.processkey = t.processkey AND 
	(( t.totalReadHeld > 10000 or t.totalWriteHeld > 10000 ) AND t.tablename = "locks") AND 
	(DATE_FORMAT(p.startTime,'%H:%i:%s') BETWEEN '10:00:00' AND '12:00:00') 
	ORDER BY p.startTime, p.endTime,p.processkey;


# Commands that were still running when server crashed

	SELECT startTime, completedLapse,cmd,user,pid
	FROM process WHERE endTime IS NULL order by startTime;

# Commands at point in time with errors

	SELECT SUBSTRING(startTime,12,19) start,pid,SUBSTRING(cmd,6,20) CMD,user,
	lineNumber line,completedLapse Lapse,error
	FROM process WHERE startTime < "2012-05-30 21:47:00"  AND endTime > "2012-05-30 21:47:02";

	SELECT SUBSTR(startTime,12,19) start,pid,SUBSTR(cmd,6,20) CMD,user,
	lineNumber line,completedLapse Lapse,error
	FROM process WHERE startTime < "2012-05-30 21:47:00"  AND endTime > "2012-05-30 21:47:02";

# Commands per user

	SELECT startTime, completedLapse,cmd,user,pid
	FROM process WHERE user = "SV-kbalasubr-dt" order by startTime;

# Commands per user per 10 mins

	SELECT SUBSTRING(startTime,1,13), count(cmd),user
	FROM process WHERE user = "saikodus" group by SUBSTRING(startTime,1,13) order by startTime;

	SELECT SUBSTR(startTime,1,13), count(cmd),user
	FROM process WHERE user = "saikodus" group by SUBSTR(startTime,1,13) order by startTime;

# Held Locks for a period of time

	SELECT p.startTime, p.user, count(distinct(p.lineNumber)), sum(t.totalReadHeld), sum(t.totalWriteHeld)  
	FROM process p, tableUse t 
	WHERE p.processkey = t.processkey AND 
	p.startTime > "2013-09-12 17:50:00" AND 
	p.startTime < "2013-09-12 18:59:00" 
	GROUP BY p.user 
	ORDER BY sum(t.totalWriteHeld) desc;


# ADDITIONAL...

Michaels Integ commands:

	"select '-n//', count(args) from process where args regexp '^-n //' and (cmd = 'user-integ' or cmd='user-integrate');"
	"select '-o//', count(args) from process where args regexp '^-o //' and (cmd = 'user-integ' or cmd='user-integrate');"
	"select '-v//', count(args) from process where args regexp '^-v //' and (cmd = 'user-integ' or cmd='user-integrate');"
	"select '-c [0-9]* //', count(args) from process where args regexp '^-c [0-9]* //' and (cmd = 'user-integ' or cmd='user-integrate');"
	"select '-c [0-9]* -v //', count(args) from process where args regexp '^-c [0-9]* -v //' and (cmd = 'user-integ' or cmd='user-integrate');"
	"select '-v -c [0-9]* //', count(args) from process where args regexp '^-v -c [0-9]* //' and (cmd = 'user-integ' or cmd='user-integrate');"
	"select '-d //', count(args) from process where args regexp '^-d //' and (cmd = 'user-integ' or cmd='user-integrate');"
	"select '-d -c [0-9]* //', count(args) from process where args regexp '^-d -c [0-9]* //' and (cmd = 'user-integ' or cmd='user-integrate');"
	"select '-c [0-9]* -v -d //', count(args) from process where args regexp '^-c [0-9]* -v -d //' and (cmd = 'user-integ' or cmd='user-integrate');"
	"select '-Ds //', count(args) from process where args regexp '^-Ds //' and (cmd = 'user-integ' or cmd='user-integrate');"
	"select '-Dt -c [0-9]* //', count(args) from process where args regexp '^-Dt -c [0-9]* //' and (cmd = 'user-integ' or cmd='user-integrate');"
	"select '-f //', count(args) from process where args regexp '-f //' and (cmd = 'user-integ' or cmd='user-integrate');"
	"select '-f -v -c [0-9]* //', count(args) from process where args regexp '^-f -v -c [0-9]* //' and (cmd = 'user-integ' or cmd='user-integrate');"
	"select '-i -d //', count(args) from process where args regexp '^-i -d //' and (cmd = 'user-integ' or cmd='user-integrate');"
	"select '-d -i //', count(args) from process where args regexp '^-d -i //' and (cmd = 'user-integ' or cmd='user-integrate');"
	"select '-i -d -f //', count(args) from process where args regexp '^-i -d -f //' and (cmd = 'user-integ' or cmd='user-integrate');"
	"select '-i -f -d //', count(args) from process where args regexp '^-i -f -d //' and (cmd = 'user-integ' or cmd='user-integrate');"
	"select '-i -d -c [0-9]* //', count(args) from process where args regexp '^-i -d -c [0-9]* //' and (cmd = 'user-integ' or cmd='user-integrate');"
	"select '-i -d -f //', count(args) from process where args regexp '^-i -d -f //' and (cmd = 'user-integ' or cmd='user-integrate');"
	"select '-i -f -c [0-9]* //', count(args) from process where args regexp '^-i -f -c [0-9]* //' and (cmd = 'user-integ' or cmd='user-integrate');"
	"select '-i -d -f //', count(args) from process where args regexp '^-i -d -f //' and (cmd = 'user-integ' or cmd='user-integrate');"
	"select '-v -i -d -c [0-9]* -b .* @.*,@.*', count(args) from process where args regexp '-v -i -d -c [0-9]* -b .* @.*,@.*' and (cmd = 'user-integ' or cmd='user-integrate');"
	"select '*', count(args) from process where  (cmd = 'user-integ' or cmd='user-integrate');"


# INTO CSV FILE - concurrent commands

	SELECT SUBSTRING(startTime,1,19),MAX(running)
	FROM process group by SUBSTRING(startTime,1,19) INTO OUTFILE "22Oct_concurrent.csv" FIELDS TERMINATED BY "," LINES TERMINATED BY "\n";

	SELECT SUBSTR(startTime,1,19),MAX(running)
	FROM process group by SUBSTR(startTime,1,19) INTO OUTFILE "22Oct_concurrent.csv" FIELDS TERMINATED BY "," LINES TERMINATED BY "\n";

# INTO CSV FILE - incoming commands

	SELECT SUBSTRING(startTime,1,19),COUNT(SUBSTRING(startTime,1,19))
	FROM process GROUP BY SUBSTRING(startTime,1,19) INTO OUTFILE "22Oct_incoming.csv" FIELDS TERMINATED BY "," LINES TERMINATED BY "\n";

	SELECT SUBSTR(startTime,1,19),COUNT(SUBSTR(startTime,1,19))
	FROM process GROUP BY SUBSTR(startTime,1,19) INTO OUTFILE "22Oct_incoming.csv" FIELDS TERMINATED BY "," LINES TERMINATED BY "\n";


# Individual blocked commands

	SELECT p.startTime, p.endTime, p.computedLapse, p.running, p.cmd, p.pid, t.tablename, MAX(t.maxReadWait), MAX(t.maxWriteWait)
	FROM process p, tableUse t WHERE p.processkey = t.processkey AND (( t.totalReadWait > 30000 or t.totalWriteWait > 30000 )) GROUP BY p.pid ORDER BY p.startTime, p.endTime;

# Individual commands that blocked

	SELECT p.startTime, p.endTime, p.running, p.cmd, p.pid, MAX(t.maxReadHeld), MAX(t.maxWriteHeld),MAX(t.maxReadWait),MAX(t.maxWriteWait)
	FROM process p, tableUse t WHERE p.processkey = t.processkey AND (( t.totalReadHeld > 30000 or t.totalWriteHeld > 30000 )) GROUP BY p.pid ORDER BY p.startTime, p.endTime;

# Individual commands that blocked with MAX table held times and Lapse

	SELECT p.startTime, FLOOR(p.endTime - p.startTime) as Lapse, p.user ,p.running, p.lineNumber, p.cmd, p.pid, FLOOR(MAX(t.maxReadHeld)/1000) AS "ReadHeld", FLOOR(MAX(t.maxWriteHeld)/1000) AS "WriteHeld"
	FROM process p, tableUse t WHERE p.processkey = t.processkey AND (( t.totalReadHeld > 30000 or t.totalWriteHeld > 30000 )) GROUP BY p.lineNumber ORDER BY p.startTime, p.endTime;


# Commands per application

	SELECT App, count(App), cast(avg(computedLapse) AS DECIMAL(9,2)) as "Avg", cast(sum(computedLapse) as decimal(9,2)) as "Sum"
	FROM process group by App order by count(App);

# Commands per application excluding sync and submit

	SELECT App, count(App), cast(avg(computedLapse) AS DECIMAL(9,2)) as "Avg", cast(sum(computedLapse) as decimal(9,2)) as "Sum"
	FROM process where (cmd != "user-sync" and cmd != "user-submit") group by App order by count(App);

# Commands per user

	SELECT user, count(user), cast(avg(computedLapse) AS DECIMAL(9,2)) as "Avg", cast(sum(computedLapse) as decimal(9,2)) as q

	select cmd, count(cmd),  cast(avg(completedLapse) AS DECIMAL(9,2)) as "Avg Completed", 
	cast(sum(completedLapse) as decimal(9,2)) as "Sum Completed",
	cast(avg(rpcsizeout) AS DECIMAL(9,2)) as "Avg Sent (MB)",
	cast(sum(rpcsizeout) AS DECIMAL(9,2)) as "Sum Sent (MB)"
	FROM process where (cmd = "user-sync")
	group by SUBSTR(endTime,1,17);

# Examples of analysing benchmark script runs

```
sqlite3 -header r40.db <<EOF
.mode column
select cmd, count(cmd),  cast(avg(completedLapse) AS DECIMAL(9,2)) as "Avg Completed", 
cast(sum(completedLapse) as decimal(9,2)) as "Sum Completed",
cast(avg(rpcsizeout) AS DECIMAL(9,2)) as "Avg Sent (MB)",
cast(sum(rpcsizeout) AS DECIMAL(9,2)) as "Sum Sent (MB)"
FROM process where (cmd = "user-sync");

select "" as "Per Minute";

select cmd, count(cmd),  SUBSTR(endTime,1,17) as "EndTime", 
cast(avg(completedLapse) AS DECIMAL(9,2)) as "Avg Completed", 
cast(sum(completedLapse) as decimal(9,2)) as "Sum Completed",
cast(avg(rpcsizeout) AS DECIMAL(9,2)) as "Avg Sent (MB)",
cast(sum(rpcsizeout) AS DECIMAL(9,2)) as "Sum Sent (MB)"
FROM process where (cmd = "user-sync")
group by SUBSTR(endTime,1,17);
EOF

sqlite3 -header r50.db <<EOF
.mode column
select cmd, count(cmd),  round(cast(avg(completedLapse) AS DECIMAL(9,2)), 2) as "Avg Time", 
cast(sum(completedLapse) as decimal(9,2)) as "Sum Time",
round(cast(avg(rpcsizeout) AS DECIMAL(9,2)), 2) as "Avg Sent(MB)",
cast(sum(rpcsizeout) AS DECIMAL(9,2)) as "Sum Sent(MB)"
FROM process where (cmd = "user-sync");

select "" as "Per Minute";

select cmd, count(cmd),  SUBSTR(endTime,1,17) as "End Time          ", 
round(cast(avg(completedLapse) AS DECIMAL(9,2)), 2) as "Avg Time", 
cast(sum(completedLapse) as decimal(9,2)) as "Sum Time",
round(cast(avg(rpcsizeout) AS DECIMAL(9,2)), 2) as "Avg Sent(MB)",
cast(sum(rpcsizeout) AS DECIMAL(9,2)) as "Sum Sent(MB)"
FROM process where (cmd = "user-sync")
group by SUBSTR(endTime,1,17);
EOF

sqlite3 -header r40.db <<EOF
.mode column
select cmd, count(cmd),  round(cast(avg(completedLapse) AS DECIMAL(9,2)), 2) as "Avg Time", 
round(cast(sum(completedLapse) as decimal(9,2)), 2) as "Sum Time",
round(cast(avg(rpcsizeout) AS DECIMAL(9,2)), 2) as "Avg Sent(MB)",
cast(sum(rpcsizeout) AS DECIMAL(9,2)) as "Sum Sent(MB)"
FROM process 
group by cmd;
EOF


sqlite3 -header r40.db <<EOF
.mode column
select cmd, count(cmd),  round(avg(completedLapse), 2) as "Avg Time", 
round(sum(completedLapse), 2) as "Sum Time",
round(avg(rpcsizeout), 2) as "Avg Sent(MB)",
sum(rpcsizeout) as "Sum Sent(MB)"
FROM process 
group by cmd;
EOF
```
