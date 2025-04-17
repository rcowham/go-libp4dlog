package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/pkg/profile"

	"github.com/machinebox/progress"
	"github.com/sirupsen/logrus"

	"github.com/perforce/p4prometheus/version"
	p4dlog "github.com/rcowham/go-libp4dlog"
	"github.com/rcowham/kingpin"
)

// Threshold in milliseconds below which we filter out commands - for at least one of read/write wait/held
var thresholdFilter int64 = 10000

func byteCountDecimal(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "kMGTPE"[exp])
}

func readerFromFile(file *os.File) (io.Reader, int64, error) {
	//create a bufio.Reader so we can 'peek' at the first few bytes
	bReader := bufio.NewReader(file)
	testBytes, err := bReader.Peek(64) //read a few bytes without consuming
	if err != nil {
		return nil, 0, err
	}
	var fileSize int64
	stat, err := file.Stat()
	if err != nil {
		return nil, 0, err
	}
	fileSize = stat.Size()

	// Detect if the content is gzipped
	contentType := http.DetectContentType(testBytes)
	if strings.Contains(contentType, "x-gzip") {
		gzipReader, err := gzip.NewReader(bReader)
		if err != nil {
			return nil, 0, err
		}
		// Estimate filesize
		return gzipReader, fileSize * 20, nil
	}
	return bReader, fileSize, nil
}

// chart header followed by data records
func writeHeader(f *bufio.Writer, thresholdFilter int64) error {
	header := `
<!DOCTYPE html>
<head>
	<meta http-equiv="Content-type" content="text/html; charset=utf-8">
	<title>Perforce Table Lock State</title>

</head>

<script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>

<style type="text/css">
	html, body { height: 100%; padding:0px; margin:0px; overflow: hidden; }
</style>
<body>

<div id="programmatic_dashboard_div" style="border: 1px solid #ccc">
<table class="columns">
  <tr>
	<td>
	  <div id="programmatic_control_div" style="padding-left: 2em; min-width: 250px"></div>
	  <div>
		<button style="margin: 1em 1em 1em 2em" id="btnChangeThreshold" onclick="drawChart();">Change Held/Wait Threshold (ms)</button>
		<input type="text" name="txtThreshold" id="txtThreshold" value="{{ .threshold }}">
		<label type="text" name="txtSummary" id="txtSummary">Data Summary</label>
	  </div>
	</td>
	<td>
	  <div id="programmatic_chart_div"></div>
	</td>
  </tr>
</table>
</div>

<div id="chart_div" style='width:100%; height:100%;'></div>
<script type="text/javascript">
	var base_data = [
`

	var buf bytes.Buffer
	templ := template.Must(template.New("myname").Parse(header))
	templ.Execute(&buf, map[string]interface{}{
		"threshold": fmt.Sprintf("%d", thresholdFilter),
	})

	_, err := fmt.Fprint(f, buf.String())
	return err
}

// chart trailer
func writeTrailer(f *bufio.Writer, params string) error {
	trailer := `
];

	var projectName = "Perforce Table Locks";
	var readHeldColor = '#5DADE2';
	var readWaitColor = '#8E44AD';
	var writeHeldColor = '#C70039';
	var writeWaitColor = '#FFC300';

	var perforceTableLockOrder = [
		"db.config",
		"db.configh",
		"db.counters",
		"db.nameval",
		"db.upgrades.rp",
		"db.upgrades",
		"db.logger",
		"db.ldap",
		"db.topology",
		"db.server",
		"db.svrview",
		"db.remote",
		"db.rmtview",
		"db.stash",
		"db.user.rp",
		"db.user",
		"db.ticket.rp",
		"db.ticket",
		"db.group",
		"db.groupx",
		"db.depot",
		"db.stream",
		"db.streamrelation",
		"db.streamview",
		"db.streamviewx",
		"db.streamq",
		"db.integedss",
		"db.domain",
		"db.template",
		"db.templatesx",
		"db.templatewx",
		"db.view.rp",
		"db.view",
		"db.haveview",
		"db.review",
		"db.label",
		"db.have.rp",
		"db.have.pt",
		"db.have",
		"db.integed",
		"db.integtx",
		"db.resolve",
		"db.resolvex",
		"db.resolveg",
		"db.scandir",
		"db.scanctl",
		"db.storagesh",
		"db.storage",
		"db.storageg",
		"db.storagesx",
		"db.storageup_R",
		"db.storageup_W",
		"db.storagemasterup_R",
		"db.storagemasterup_W",
		"db.revdx",
		"db.revhx",
		"db.revpx",
		"db.revsx",
		"db.revsh",
		"db.revbx",
		"db.revux",
		"db.revcx",
		"db.rev",
		"db.revtx",
		"db.revstg",
		"db.revfs",
		"db.locks",
		"db.locksg",
		"db.working",
		"db.workingx",
		"db.workingg",
		"db.haveg",
		"db.excl",
		"db.exclg",
		"db.exclgx",
		"db.traits",
		"db.trigger",
		"db.change",
		"db.changex",
		"db.changeidx",
		"db.desc",
		"db.repo",
		"db.refhist",
		"db.ref",
		"db.refcntadjust",
		"db.object",
		"db.graphindex",
		"db.graphperm",
		"db.submodule",
		"db.pubkey",
		"db.job",
		"db.fix",
		"db.fixrev",
		"db.bodresolve",
		"db.bodresolvex",
		"db.bodtext",
		"db.bodtextcx",
		"db.bodtexthx",
		"db.bodtextsx",
		"db.bodtextwx",
		"db.ixtext",
		"db.ixtexthx",
		"db.uxtext",
		"db.protect",
		"db.property",
		"db.message",
		"db.sendq",
		"db.sendq.pt",
		"db.jnlack",
		"db.monitor",
	];

	function pad2(i) {
		if (i < 10) {
			return "0" + i;
		}
		return i;
	}

	function dateToGanttDate(d) {
		return d.getFullYear() + "-" +  pad2(d.getMonth()) + "-" + pad2(d.getDate()) +
			" " + pad2(d.getHours()) + ":" + pad2(d.getMinutes()) + ":" + pad2(d.getSeconds());
	}

	function secondsToDuration(s) {
		var minute = 60;
		var hour = minute * 60;

		var numHours = Math.floor(s/hour);
		var hourRemainder = s % hour;
		var numMinutes = Math.floor(hourRemainder/minute);
		var minuteRemainder = hourRemainder % minute;

		var result = "";
		if (numHours > 0) {
			result += numHours + "h";
		}
		if (numMinutes > 0) {
			result += numMinutes + "m";
		}
		if (minuteRemainder > 0) {
			result += minuteRemainder + "s";
		}
		return result;
	}

	function toMilliseconds(d) {
		return d; // null function now - expects to be pass millis
	}

	function humanize (milliseconds) {
		var seconds = Math.floor(milliseconds / 1000);
		var levels = [
			[Math.floor(seconds / 31536000), 'years'],
			[Math.floor((seconds % 31536000) / 86400), 'days'],
			[Math.floor(((seconds % 31536000) % 86400) / 3600), 'hours'],
			[Math.floor((((seconds % 31536000) % 86400) % 3600) / 60), 'mins'],
			[(((seconds % 31536000) % 86400) % 3600) % 60, 'secs'],
		];
		var returntext = '';

		for (var i = 0, max = levels.length; i < max; i++) {
			if ( levels[i][0] === 0 ) continue;
			returntext += ' ' + levels[i][0] + ' ' + (levels[i][0] === 1 ? levels[i][1].substr(0, levels[i][1].length-1): levels[i][1]);
		};
		if (returntext == '') { returntext = milliseconds + 'ms'}
		return returntext.trim();
	}

	function getTooltip(command, duration) {
		var cmdText = command.Command;
		if (cmdText.length > 100) { 
			cmdText = cmdText.substring(0, 100) + "..."
		};
		return "Pid:" + command.Pid + " line:" + command.Line + " User:" + command.User + " Running: " + command.Running + "</br>" +
			"Dur: " + duration + " (" + humanize(duration) + ") Start:" + command.Start + " End:" + command.EndTime + "</br>" +
			"Completed: " + command.CompletedLapse + " (" + humanize(command.CompletedLapse) + ")" + " Compute: " + command.ComputeLapse + " (" + humanize(command.ComputeLapse) + ")" + "</br>" +
			" " + cmdText;
	}

	function processLockEvents(input) {
		var data = new google.visualization.DataTable();
		data.addColumn({ type: 'string', id: 'Position' });
		data.addColumn({ type: 'string', id: 'Name' });
		data.addColumn({ type: 'string', id: 'style', role: 'style' });
		data.addColumn({ type: 'string', role: 'tooltip', 'p': {'html': true} });
		data.addColumn({ type: 'date', id: 'Start' });
		data.addColumn({ type: 'date', id: 'End' });

		var index = 1;
		var tables = new Map();

		for ( var i = 0; i < input.length; i++) {
			var command = input[i];
			var parentTable = tables.get(command.Table);

			var startTime = command.Start.slice(0,command.Start.length-1).replace("T", " ");
			var start = new Date(startTime);

			var read_start = start;
			var read_end = start;

			if (command.Read) {
				var rows = [];

				if (command.Read.Wait > 0) {
					read_end = new Date(read_end.getTime() + toMilliseconds(command.Read.Wait));
					rows.push([
							command.Table,
							"Read Wait" + " ("+command.Pid+")",
							readWaitColor,
							getTooltip(command, command.Read.Wait),
							read_start,
							read_end
					]);
				}

				if (command.Read.Held > 0) {
					read_start = read_end;
					read_end = new Date(read_end.getTime() + toMilliseconds(command.Read.Held));
					rows.push([
							command.Table,
							"Read Held" + " ("+command.Pid+")",
							readHeldColor,
							getTooltip(command, command.Read.Held),
							read_start,
							read_end
					]);
				}
				if (rows.length > 0){
					data.addRows(rows);
				}
			}

			var write_start = start;
			var write_end = start
			if (command.Write) {
				var rows = [];

				if (command.Write.Wait > 0) {
					write_end = new Date(write_end.getTime() + toMilliseconds(command.Write.Wait));
					rows.push([
							command.Table,
							"Write Wait" + " ("+command.Pid+")",
							writeWaitColor,
							getTooltip(command, command.Write.Wait),
							write_start,
							write_end
					]);
				}

				if (command.Write.Held > 0) {
					write_start = write_end;
					write_end = new Date(write_end.getTime() + toMilliseconds(command.Write.Held));
					rows.push([
							command.Table,
							"Write Held" + " ("+command.Pid+")",
							writeHeldColor,
							getTooltip(command, command.Write.Held),
							write_start,
							write_end
					]);
				}
				if (rows.length > 0){
					data.addRows(rows);
				}
			}
		}

		return data;
	}

	function drawChart() {
		var chart = new google.visualization.Timeline(document.getElementById('chart_div'));
		var threshold = document.getElementById('txtThreshold').value;
		data = base_data.filter(item => perforceTableLockOrder.indexOf(item.Table) != -1); 
		data = data.filter(item => item.MaxLock > threshold); 
		document.getElementById('txtSummary').innerHTML = 'Records - total: ' + base_data.length + ' filtered: ' + data.length + ' ({{ .params }})';
		data.sort(function(a, b){
			var atable = perforceTableLockOrder.indexOf(a.Table);
			var btable =  perforceTableLockOrder.indexOf(b.Table);			
			return atable - btable;
		});
		var options = {
			timeline: { 
			rowLabelStyle: {fontSize: 24, "vertical-align": "top" },
			tooltip: { isHtml: true }
		}};
		chart.draw(processLockEvents(data), options);
	}

	// Pressing Enter key in threshold textbox will cause button to be clicked
	document.getElementById("txtThreshold").addEventListener("keyup", function(event) {
		event.preventDefault();
		if (event.keyCode === 13) {
			document.getElementById("btnChangeThreshold").click();
		}
	});

	google.charts.load("current", {packages:["timeline"]});
	google.charts.setOnLoadCallback(drawChart);

</script>

</body>
`

	var buf bytes.Buffer
	templ := template.Must(template.New("myname").Parse(trailer))
	templ.Execute(&buf, map[string]interface{}{
		"params": params,
	})

	_, err := fmt.Fprint(f, buf.String())
	return err
}

type LockRec struct {
	TotalWait int64 `json:"Wait"`
	TotalHeld int64 `json:"Held"`
}

// DataRec is a command found in the block
type DataRec struct {
	Table          string    `json:"Table"`
	Pid            int64     `json:"Pid"`
	CmdArgs        string    `json:"Command"`
	LineNo         int64     `json:"Line"`
	User           string    `json:"User"`
	StartTime      time.Time `json:"Start"`
	EndTime        time.Time `json:"EndTime"`
	Workspace      string    `json:"Workspace"`
	ComputeLapse   int64     `json:"ComputeLapse"`
	CompletedLapse int64     `json:"CompletedLapse"`
	App            string    `json:"App"`
	Running        int64     `json:"Running"`
	UCpu           int64     `json:"UCpu"`
	SCpu           int64     `json:"SCpu"`
	MaxLock        int64     `json:"MaxLock"` // Max of any read/write wait/held value - for filtering results
	ReadLock       *LockRec  `json:"Read,omitempty"`
	WriteLock      *LockRec  `json:"Write,omitempty"`
}

func (d *DataRec) setMaxLock() {
	if d.ReadLock != nil {
		if d.ReadLock.TotalHeld > d.ReadLock.TotalWait {
			d.MaxLock = d.ReadLock.TotalHeld
		} else {
			d.MaxLock = d.ReadLock.TotalWait
		}
	}
	if d.WriteLock != nil {
		if d.WriteLock.TotalHeld > d.WriteLock.TotalWait {
			d.MaxLock = d.WriteLock.TotalHeld
		} else {
			d.MaxLock = d.WriteLock.TotalWait
		}
	}
}

// P4DLocks structure
type P4DLocks struct {
	debug               int
	fp                  *p4dlog.P4dFileParser
	excludeTablesString string
	excludeTablesRegex  *regexp.Regexp
	logger              *logrus.Logger
	linesChan           chan string
	countTotal          int
	countOutput         int
}

//	{
//		"Table": "db.revsx",
//		"Pid": 72052,
//		"Command": "user-sync -n //data/...",
//		"User": "build",
//		"Start": "2022-02-02T15:15:14Z",
//		"Read": {
//			"Wait": 0,
//			"Held": 554000000
//		}
//	}
func (pl *P4DLocks) writeCmd(f *bufio.Writer, cmd *p4dlog.Command) error {
	for _, t := range cmd.Tables {
		if pl.excludeTablesString != "" {
			if pl.excludeTablesRegex == nil {
				regexStr := fmt.Sprintf("(%s)", pl.excludeTablesString)
				pl.excludeTablesRegex = regexp.MustCompile(regexStr)
			}
			if pl.excludeTablesRegex.MatchString(t.TableName) {
				continue
			}
		}
		if t.TotalReadHeld > thresholdFilter || t.TotalReadWait > thresholdFilter ||
			t.TotalWriteHeld > thresholdFilter || t.TotalWriteWait > thresholdFilter {
			rec := DataRec{
				CmdArgs:        fmt.Sprintf("%s %s", cmd.Cmd, cmd.Args),
				Pid:            cmd.Pid,
				Table:          fmt.Sprintf("db.%s", t.TableName),
				User:           cmd.User,
				LineNo:         cmd.LineNo,
				StartTime:      cmd.StartTime,
				EndTime:        cmd.EndTime,
				Workspace:      cmd.Workspace,
				ComputeLapse:   int64(cmd.ComputeLapse * 1000),
				CompletedLapse: int64(cmd.CompletedLapse * 1000),
				App:            cmd.App,
				Running:        cmd.Running,
				UCpu:           int64(cmd.UCpu * 1000),
				SCpu:           int64(cmd.SCpu * 1000),
			}
			if t.TotalReadHeld > thresholdFilter || t.TotalReadWait > thresholdFilter {
				rec.ReadLock = &LockRec{
					TotalWait: t.TotalReadWait,
					TotalHeld: t.TotalReadHeld,
				}
				rec.setMaxLock()
				j, _ := json.Marshal(rec)
				if pl.countOutput > 0 {
					_, err := fmt.Fprintf(f, ",\n")
					if err != nil {
						return err
					}
				}
				_, err := fmt.Fprintf(f, "%s", string(j))
				if err != nil {
					return err
				}
				pl.countOutput += 1
			}
			if t.TotalWriteHeld > thresholdFilter || t.TotalWriteWait > thresholdFilter {
				rec.ReadLock = nil
				rec.WriteLock = &LockRec{
					TotalWait: t.TotalWriteWait,
					TotalHeld: t.TotalWriteHeld,
				}
				rec.setMaxLock()
				j, _ := json.Marshal(rec)
				if pl.countOutput > 0 {
					_, err := fmt.Fprintf(f, ",\n")
					if err != nil {
						return err
					}
				}
				_, err := fmt.Fprintf(f, "%s", string(j))
				if err != nil {
					return err
				}
				pl.countOutput += 1
			}
		}
	}
	return nil
}

// Parse single log file - output is sent via linesChan channel
func (pl *P4DLocks) parseLog(logfile string) {
	var file *os.File
	if logfile == "-" {
		file = os.Stdin
	} else {
		var err error
		file, err = os.Open(logfile)
		if err != nil {
			pl.logger.Fatal(err)
		}
	}
	defer file.Close()

	const maxCapacity = 5 * 1024 * 1024
	ctx := context.Background()
	inbuf := make([]byte, maxCapacity)
	reader, fileSize, err := readerFromFile(file)
	if err != nil {
		pl.logger.Fatalf("Failed to open file: %v", err)
	}
	pl.logger.Debugf("Opened %s, size %v", logfile, fileSize)
	reader = bufio.NewReaderSize(reader, maxCapacity)
	preader := progress.NewReader(reader)
	scanner := bufio.NewScanner(preader)
	scanner.Buffer(inbuf, maxCapacity)

	// Start a goroutine printing progress
	go func() {
		d := 1 * time.Second
		if fileSize > 1*1000*1000*1000 {
			d = 10 * time.Second
		}
		if fileSize > 10*1000*1000*1000 {
			d = 30 * time.Second
		}
		if fileSize > 25*1000*1000*1000 {
			d = 60 * time.Second
		}
		pl.logger.Infof("Progress reporting frequency: %v", d)
		progressChan := progress.NewTicker(ctx, preader, fileSize, d)
		for p := range progressChan {
			fmt.Fprintf(os.Stderr, "%s: %s/%s %.0f%% estimated finish %s, %v remaining... cmds total %d\n",
				logfile, byteCountDecimal(p.N()), byteCountDecimal(fileSize),
				p.Percent(), p.Estimated().Format("15:04:05"),
				p.Remaining().Round(time.Second),
				pl.countTotal)
		}
		fmt.Fprintln(os.Stderr, "processing completed")
	}()

	const maxLine = 10000
	i := 0
	for scanner.Scan() {
		// Use time records in log to cause ticks for log parser
		if len(scanner.Text()) > maxLine {
			line := fmt.Sprintf("%s...'", scanner.Text()[0:maxLine])
			pl.linesChan <- line
		} else {
			pl.linesChan <- scanner.Text()
		}
		i += 1
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read input file on line: %d, %v\n", i, err)
	}

}

func (p4p *P4DLocks) processEvents(logfiles []string) {

	for _, f := range logfiles {
		p4p.logger.Infof("Processing: %s", f)
		p4p.parseLog(f)
	}
	p4p.logger.Infof("Finished all log files")
	close(p4p.linesChan)

}

func getFilename(name, suffix string, requireSuffix bool, logfiles []string) string {
	if name == "" {
		if len(logfiles) == 0 {
			name = "logs"
		} else {
			name = strings.TrimSuffix(logfiles[0], ".gz")
			name = strings.TrimSuffix(name, ".log")
		}
		if !requireSuffix && !strings.HasSuffix(name, suffix) {
			name = fmt.Sprintf("%s%s", name, suffix)
		}
	}
	// Check again
	if requireSuffix && !strings.HasSuffix(name, suffix) {
		name = fmt.Sprintf("%s%s", name, suffix)
	}
	return name
}

func getHTMLFilename(name string, logfiles []string) string {
	return getFilename(name, ".html", false, logfiles)
}

func openFile(outputName string) (*os.File, *bufio.Writer, error) {
	var fd *os.File
	var err error
	if outputName == "-" {
		fd = os.Stdout
	} else {
		fd, err = os.OpenFile(outputName, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, nil, err
		}
	}
	return fd, bufio.NewWriterSize(fd, 1024*1024), nil
}

func main() {
	// Tracing code
	// ft, err := os.Create("trace.out")
	// if err != nil {
	// 	panic(err)
	// }
	// defer ft.Close()
	// err = trace.Start(ft)
	// if err != nil {
	// 	panic(err)
	// }
	// defer trace.Stop()
	// End of trace code
	var err error
	var (
		logfiles = kingpin.Arg(
			"logfile",
			"Log files to process (may be gzipped).").Strings()
		debug = kingpin.Flag(
			"debug",
			"Enable debugging level.",
		).Int()
		threshold = kingpin.Flag(
			"threshold",
			fmt.Sprintf("Threshold value below which commands are filtered out (in milliseconds). Default %d", thresholdFilter),
		).Short('t').Int()
		htmlOutputFile = kingpin.Flag(
			"html.output",
			"Name of file to which to write HTML. Defaults to <logfile-prefix>.html",
		).Short('o').String()
		excludeTablesRegexString = kingpin.Flag(
			"exclude.tables",
			"Specify a (golang) regex to match tables to exclude from results (e.g. 'user$' or '(user|nameval)$'). No default.",
		).Short('x').String()
	)
	kingpin.UsageTemplate(kingpin.CompactUsageTemplate).Version(version.Print("p4locks")).Author("Robert Cowham")
	kingpin.CommandLine.Help = `Parses one or more p4d text log files (which may be gzipped) and outputs an HTML file with a Google Charts timeline with information about locks.
Locks are listed by table and then pids with read/write wait/held.
The output file can be opened locally by any browser (although internet access required to download JS).

Usage examples:

Exclude "db.user" table:
	p4locks -x user log

Use a lower default threshold (ms):
	p4locks -t 1000 my.log

Process multiple log files (gzipped or not) into single output file:
	p4locks -o report.html log-2023-*.gz
`
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	// Validate regex
	if len(*excludeTablesRegexString) > 0 {
		if _, err := regexp.Compile(*excludeTablesRegexString); err != nil {
			fmt.Printf("ERROR: Failed to parse parameter '%s' as a valid Go regex\n", *excludeTablesRegexString)
			os.Exit(1)
		}
	}

	if *debug > 0 {
		// CPU profiling by default
		defer profile.Start().Stop()
	}
	logger := logrus.New()
	logger.Level = logrus.InfoLevel
	if *debug > 0 {
		logger.Level = logrus.DebugLevel
	}

	if len(*logfiles) == 0 {
		logger.Errorf("No log file specified!")
		os.Exit(1)
	}

	missingLogs := make([]string, 0)
	for _, f := range *logfiles {
		_, err := os.Stat(f)
		if os.IsNotExist(err) {
			missingLogs = append(missingLogs, f)
		}
	}
	if len(missingLogs) > 0 {
		logger.Errorf("Specified log files not found: %s", missingLogs)
		os.Exit(1)
	}

	if *threshold > 0 {
		thresholdFilter = int64(*threshold)
	}
	startTime := time.Now()
	logger.Infof("%v", version.Print("p4locks"))
	logger.Infof("Starting %s, Logfiles: %v", startTime, *logfiles)
	logger.Infof("Flags: debug %v, htmlfile %v, threshold (ms) %v", *debug, *htmlOutputFile, *threshold)

	linesChan := make(chan string, 10000)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var fHTML *bufio.Writer
	var fdHTML *os.File
	htmlFilename := getHTMLFilename(*htmlOutputFile, *logfiles)
	fdHTML, fHTML, err = openFile(htmlFilename)
	if err != nil {
		logger.Fatal(err)
	}
	defer fdHTML.Close()
	defer fHTML.Flush()
	logger.Infof("Creating HTML output: %s", htmlFilename)

	var wg sync.WaitGroup
	var fp *p4dlog.P4dFileParser
	var cmdChan chan interface{}

	fp = p4dlog.NewP4dFileParser(logger)
	pl := &P4DLocks{
		debug:               *debug,
		excludeTablesString: *excludeTablesRegexString,
		logger:              logger,
		fp:                  fp,
		linesChan:           linesChan,
	}
	if *debug > 0 {
		fp.SetDebugMode(*debug)
	}
	cmdChan = fp.LogParser(ctx, linesChan)

	// Process all input files, sending lines into linesChan
	wg.Add(1)

	go func() {
		defer wg.Done()
		pl.processEvents(*logfiles)
	}()

	err = writeHeader(fHTML, thresholdFilter)
	if err != nil {
		logger.Errorf("Failed to write header: %v", err)
	}
	// Process all commands, filtering only those greater than a threshold of read/write wait/held
	for cmd := range cmdChan {
		switch cmd := cmd.(type) {
		case p4dlog.Command:
			pl.countTotal += 1
			err := pl.writeCmd(fHTML, &cmd)
			if err != nil {
				logger.Errorf("Failed to write cmd: %v", err)
			}
			if pl.countTotal%1000 == 0 {
				fHTML.Flush()
			}
		}
	}
	err = writeTrailer(fHTML, fmt.Sprintf("extraction threshold (ms): %d, excluded tables: %s", thresholdFilter, pl.excludeTablesString))
	if err != nil {
		logger.Errorf("Failed to write trailer: %v", err)
	}

	wg.Wait()
	logger.Infof("Completed %s, elapsed %s, cmds total %d, filtered output count %d",
		time.Now(), time.Since(startTime), pl.countTotal, pl.countOutput)
}
