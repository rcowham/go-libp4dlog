package metrics

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	p4dlog "github.com/rcowham/go-libp4dlog"
	"github.com/sirupsen/logrus"
)

var (
	eol    = regexp.MustCompile("\r\n|\n")
	logger = &logrus.Logger{Out: os.Stderr,
		Formatter: &logrus.TextFormatter{TimestampFormat: "15:04:05.000", FullTimestamp: true},
		// Level:     logrus.DebugLevel}
		Level: logrus.InfoLevel}
)

func getResult(output chan string) []string {
	lines := []string{}
	for line := range output {
		lines = append(lines, line)
	}
	return lines
}

func funcName() string {
	fpcs := make([]uintptr, 1)
	// Skip 2 levels to get the caller
	n := runtime.Callers(2, fpcs)
	if n == 0 {
		return ""
	}
	caller := runtime.FuncForPC(fpcs[0] - 1)
	if caller == nil {
		return ""
	}
	return caller.Name()
}

// Assuming there are several outputs - this returns the latest one unless historical
func getOutput(testchan chan string, historical bool) []string {
	result := make([]string, 0)
	lastoutput := ""
	if historical {
		for output := range testchan {
			for _, line := range eol.Split(output, -1) {
				if len(line) > 0 && !strings.HasPrefix(line, "#") {
					result = append(result, line)
				}
			}
		}
	} else {
		for output := range testchan {
			lastoutput = output
		}
		for _, line := range eol.Split(lastoutput, -1) {
			if len(line) > 0 && !strings.HasPrefix(line, "#") {
				result = append(result, line)
			}
		}
	}
	sort.Strings(result)
	return result
}

func basicTest(t *testing.T, cfg *Config, input string, historical bool) []string {
	logrus.SetFormatter(&logrus.TextFormatter{TimestampFormat: "15:04:05.000", FullTimestamp: true})
	logger.SetReportCaller(true)
	logger.Debugf("Function: %s", funcName())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fp := p4dlog.NewP4dFileParser(logger)
	fp.SetDebugMode(255)
	// Shorten durations for testing
	fp.SetDurations(10*time.Millisecond, 20*time.Millisecond)
	linesChan := make(chan string, 100)

	p4m := NewP4DMetricsLogParser(cfg, logger, historical)
	p4m.fp = fp

	var wg sync.WaitGroup

	_, metricsChan := p4m.ProcessEvents(ctx, linesChan, false)

	for _, l := range eol.Split(input, -1) {
		linesChan <- l
	}
	close(linesChan)

	output := []string{}

	go func() {
		defer wg.Done()
		logger.Debugf("Waiting for metrics")
		output = getOutput(metricsChan, historical)
	}()

	wg.Add(1)
	logger.Debugf("Waiting for finish")
	wg.Wait()
	logger.Debugf("Finished")
	return output
}

func compareOutput(t *testing.T, expected, actual []string) {
	nExpected := make([]string, 0)
	nActual := make([]string, 0)
	for _, line := range expected {
		if !strings.HasPrefix(line, "p4_prom_cmds_pending") {
			nExpected = append(nExpected, line)
		}
	}
	for _, line := range actual {
		if !strings.HasPrefix(line, "p4_prom_cmds_pending") {
			nActual = append(nActual, line)
		}
	}
	sort.Strings(nActual)
	sort.Strings(nExpected)
	assert.Equal(t, nExpected, nActual)
}

func TestP4PromBasic(t *testing.T) {
	cfg := &Config{
		ServerID:         "myserverid",
		UpdateInterval:   10 * time.Millisecond,
		OutputCmdsByUser: true}
	input := `
Perforce server info:
	2015/09/02 15:23:09 pid 1616 robert@robert-test 127.0.0.1 [p4/2016.2/LINUX26X86_64/1598668] 'user-sync //...'
Perforce server info:
	2015/09/02 15:23:09 pid 1616 compute end .031s
Perforce server info:
	Server network estimates: files added/updated/deleted=1/3/2, bytes added/updated=123/456
Perforce server info:
	2015/09/02 15:23:09 pid 1616 completed .031s
`
	cmdTime, _ := time.Parse(p4timeformat, "2015/09/02 15:23:09")
	historical := false
	output := basicTest(t, cfg, input, historical)

	assert.Equal(t, 17, len(output))
	expected := eol.Split(`p4_cmd_counter{serverid="myserverid",cmd="user-sync"} 1
p4_cmd_cumulative_seconds{serverid="myserverid",cmd="user-sync"} 0.031
p4_cmd_program_counter{serverid="myserverid",program="p4/2016.2/LINUX26X86_64/1598668"} 1
p4_cmd_program_cumulative_seconds{serverid="myserverid",program="p4/2016.2/LINUX26X86_64/1598668"} 0.031
p4_cmd_running{serverid="myserverid"} 1
p4_cmd_user_counter{serverid="myserverid",user="robert"} 1
p4_cmd_cpu_system_cumulative_seconds{serverid="myserverid",cmd="user-sync"} 0.000
p4_cmd_cpu_user_cumulative_seconds{serverid="myserverid",cmd="user-sync"} 0.000
p4_cmd_user_cumulative_seconds{serverid="myserverid",user="robert"} 0.031
p4_prom_cmds_pending{serverid="myserverid"} 0
p4_prom_cmds_processed{serverid="myserverid"} 1
p4_prom_log_lines_read{serverid="myserverid"} 10
p4_sync_bytes_added{serverid="myserverid"} 123
p4_sync_bytes_updated{serverid="myserverid"} 456
p4_sync_files_added{serverid="myserverid"} 1
p4_sync_files_deleted{serverid="myserverid"} 2
p4_sync_files_updated{serverid="myserverid"} 3`, -1)
	compareOutput(t, expected, output)

	historical = true
	output = basicTest(t, cfg, input, historical)

	assert.Equal(t, 17, len(output))
	// Cross check appropriate time is being produced for historical runs
	assert.Contains(t, output[0], fmt.Sprintf("%d", cmdTime.Unix()))
	expected = eol.Split(`p4_cmd_counter;serverid=myserverid;cmd=user-sync 1 1441207389
p4_cmd_cumulative_seconds;serverid=myserverid;cmd=user-sync 0.031 1441207389
p4_cmd_program_counter;serverid=myserverid;program=p4/2016.2/LINUX26X86_64/1598668 1 1441207389
p4_cmd_program_cumulative_seconds;serverid=myserverid;program=p4/2016.2/LINUX26X86_64/1598668 0.031 1441207389
p4_cmd_running;serverid=myserverid 1 1441207389
p4_cmd_user_counter;serverid=myserverid;user=robert 1 1441207389
p4_cmd_cpu_system_cumulative_seconds;serverid=myserverid;cmd=user-sync 0.000 1441207389
p4_cmd_cpu_user_cumulative_seconds;serverid=myserverid;cmd=user-sync 0.000 1441207389
p4_cmd_user_cumulative_seconds;serverid=myserverid;user=robert 0.031 1441207389
p4_prom_cmds_pending;serverid=myserverid 0 1441207389
p4_prom_cmds_processed;serverid=myserverid 1 1441207389
p4_prom_log_lines_read;serverid=myserverid 10 1441207389
p4_sync_bytes_added;serverid=myserverid 123 1441207389
p4_sync_bytes_updated;serverid=myserverid 456 1441207389
p4_sync_files_added;serverid=myserverid 1 1441207389
p4_sync_files_deleted;serverid=myserverid 2 1441207389
p4_sync_files_updated;serverid=myserverid 3 1441207389`, -1)
	compareOutput(t, expected, output)

}

// Tests network estimates counting
func TestP4PromSyncData(t *testing.T) {
	cfg := &Config{
		ServerID:         "myserverid",
		UpdateInterval:   10 * time.Millisecond,
		OutputCmdsByUser: true}
	input := `
Perforce server info:
	2015/09/02 15:23:09 pid 1616 robert@robert-test 127.0.0.1 [p4/2016.2/LINUX26X86_64/1598668] 'user-sync //...'
Perforce server info:
	2015/09/02 15:23:09 pid 1616 compute end .031s
Perforce server info:
	Server network estimates: files added/updated/deleted=1/3/2, bytes added/updated=123/456
Perforce server info:
	2015/09/02 15:23:09 pid 1616 completed .031s

Perforce server info:
	2015/09/02 16:23:10 pid 1617 robert@robert-test 127.0.0.1 [p4/2016.2/LINUX26X86_64/1598668] 'user-sync //...'
Perforce server info:
	2015/09/02 16:23:10 pid 1617 compute end .041s
Perforce server info:
	Server network estimates: files added/updated/deleted=1/3/2, bytes added/updated=123/456
Perforce server info:
	2015/09/02 16:23:10 pid 1617 completed .031s
`
	cmdTime, _ := time.Parse(p4timeformat, "2015/09/02 16:23:10")
	historical := true
	output := basicTest(t, cfg, input, historical)

	assert.Equal(t, 26, len(output))
	// Cross check appropriate time is being produced for historical runs
	assert.Contains(t, output[0], fmt.Sprintf("%d", cmdTime.Unix()))
	expected := eol.Split(`p4_cmd_counter;serverid=myserverid;cmd=user-sync 2 1441210990
p4_cmd_cumulative_seconds;serverid=myserverid;cmd=user-sync 0.062 1441210990
p4_cmd_program_counter;serverid=myserverid;program=p4/2016.2/LINUX26X86_64/1598668 2 1441210990
p4_cmd_program_cumulative_seconds;serverid=myserverid;program=p4/2016.2/LINUX26X86_64/1598668 0.062 1441210990
p4_cmd_running;serverid=myserverid 0 1441210990
p4_cmd_running;serverid=myserverid 1 1441210990
p4_cmd_user_counter;serverid=myserverid;user=robert 2 1441210990
p4_cmd_cpu_system_cumulative_seconds;serverid=myserverid;cmd=user-sync 0.000 1441210990
p4_cmd_cpu_user_cumulative_seconds;serverid=myserverid;cmd=user-sync 0.000 1441210990
p4_cmd_user_cumulative_seconds;serverid=myserverid;user=robert 0.062 1441210990
p4_prom_cmds_processed;serverid=myserverid 0 1441210990
p4_prom_cmds_processed;serverid=myserverid 2 1441210990
p4_prom_log_lines_read;serverid=myserverid 12 1441210990
p4_prom_log_lines_read;serverid=myserverid 19 1441210990
p4_sync_bytes_added;serverid=myserverid 0 1441210990
p4_sync_bytes_added;serverid=myserverid 246 1441210990
p4_sync_bytes_updated;serverid=myserverid 0 1441210990
p4_sync_bytes_updated;serverid=myserverid 912 1441210990
p4_sync_files_added;serverid=myserverid 0 1441210990
p4_sync_files_added;serverid=myserverid 2 1441210990
p4_sync_files_deleted;serverid=myserverid 0 1441210990
p4_sync_files_deleted;serverid=myserverid 4 1441210990
p4_sync_files_updated;serverid=myserverid 0 1441210990
p4_sync_files_updated;serverid=myserverid 6 1441210990`, -1)
	compareOutput(t, expected, output)

}

func TestP4PromBasicNoUser(t *testing.T) {
	cfg := &Config{
		ServerID:         "myserverid",
		UpdateInterval:   20 * time.Millisecond,
		OutputCmdsByUser: false}

	input := `
Perforce server info:
	2015/09/02 15:23:09 pid 1616 robert@robert-test 127.0.0.1 [some unknown prog=p4python!v2] 'user-sync //...'
Perforce server info:
	2015/09/02 15:23:09 pid 1616 compute end .031s
Perforce server info:
	2015/09/02 15:23:09 pid 1616 completed .031s
`

	cmdTime, _ := time.Parse(p4timeformat, "2015/09/02 15:23:09")
	historical := false
	output := basicTest(t, cfg, input, historical)

	assert.Equal(t, 15, len(output))
	expected := eol.Split(`p4_cmd_counter{serverid="myserverid",cmd="user-sync"} 1
p4_cmd_cumulative_seconds{serverid="myserverid",cmd="user-sync"} 0.031
p4_cmd_program_counter{serverid="myserverid",program="some_unknown_prog_p4python_v2"} 1
p4_cmd_program_cumulative_seconds{serverid="myserverid",program="some_unknown_prog_p4python_v2"} 0.031
p4_cmd_running{serverid="myserverid"} 1
p4_cmd_cpu_system_cumulative_seconds{serverid="myserverid",cmd="user-sync"} 0.000
p4_cmd_cpu_user_cumulative_seconds{serverid="myserverid",cmd="user-sync"} 0.000
p4_prom_cmds_pending{serverid="myserverid"} 0
p4_prom_cmds_processed{serverid="myserverid"} 1
p4_prom_log_lines_read{serverid="myserverid"} 8
p4_sync_bytes_added{serverid="myserverid"} 0
p4_sync_bytes_updated{serverid="myserverid"} 0
p4_sync_files_added{serverid="myserverid"} 0
p4_sync_files_deleted{serverid="myserverid"} 0
p4_sync_files_updated{serverid="myserverid"} 0`, -1)
	compareOutput(t, expected, output)

	historical = true
	output = basicTest(t, cfg, input, historical)

	assert.Equal(t, 15, len(output))
	// Cross check appropriate time is being produced for historical runs
	assert.Contains(t, output[0], fmt.Sprintf("%d", cmdTime.Unix()))
	expected = eol.Split(`p4_cmd_counter;serverid=myserverid;cmd=user-sync 1 1441207389
p4_cmd_cumulative_seconds;serverid=myserverid;cmd=user-sync 0.031 1441207389
p4_cmd_program_counter;serverid=myserverid;program=some_unknown_prog_p4python_v2 1 1441207389
p4_cmd_program_cumulative_seconds;serverid=myserverid;program=some_unknown_prog_p4python_v2 0.031 1441207389
p4_cmd_running;serverid=myserverid 1 1441207389
p4_cmd_cpu_system_cumulative_seconds;serverid=myserverid;cmd=user-sync 0.000 1441207389
p4_cmd_cpu_user_cumulative_seconds;serverid=myserverid;cmd=user-sync 0.000 1441207389
p4_prom_cmds_pending;serverid=myserverid 0 1441207389
p4_prom_cmds_processed;serverid=myserverid 1 1441207389
p4_prom_log_lines_read;serverid=myserverid 8 1441207389
p4_sync_bytes_added;serverid=myserverid 0 1441207389
p4_sync_bytes_updated;serverid=myserverid 0 1441207389
p4_sync_files_added;serverid=myserverid 0 1441207389
p4_sync_files_deleted;serverid=myserverid 0 1441207389
p4_sync_files_updated;serverid=myserverid 0 1441207389`, -1)
	compareOutput(t, expected, output)
}

func TestP4PromBasicHistorical(t *testing.T) {
	// Test with multiple outputs
	cfg := &Config{
		ServerID:         "myserverid",
		UpdateInterval:   10 * time.Millisecond,
		OutputCmdsByUser: false}

	input := `
Perforce server info:
	2015/09/02 15:23:09 pid 1616 robert@robert-test 127.0.0.1 [p4/2016.2/LINUX26X86_64/1598668] 'user-sync //...'
Perforce server info:
	2015/09/02 15:23:09 pid 1616 compute end .031s
Perforce server info:
	2015/09/02 15:23:09 pid 1616 completed .031s

Perforce server info:
	2015/09/02 15:24:10 pid 1617 robert@robert-test 127.0.0.1 [p4/2016.2/LINUX26X86_64/1598668] 'user-sync //...'
Perforce server info:
	2015/09/02 15:24:10 pid 1617 compute end .032s
Perforce server info:
	2015/09/02 15:24:10 pid 1617 completed .032s

Perforce server info:
	2015/09/02 15:25:11 pid 1617 robert@robert-test 127.0.0.1 [p4/2016.2/LINUX26X86_64/1598668] 'user-sync //...'
Perforce server info:
	2015/09/02 15:25:11 pid 1617 compute end .033s
Perforce server info:
	2015/09/02 15:25:11 pid 1617 completed .033s
`

	cmdTime, _ := time.Parse(p4timeformat, "2015/09/02 15:25:11")
	historical := true
	output := basicTest(t, cfg, input, historical)

	assert.Equal(t, 33, len(output))
	// Cross check appropriate time is being produced for historical runs
	assert.Contains(t, output[0], fmt.Sprintf("%d", cmdTime.Unix()))
	expected := eol.Split(`p4_cmd_counter;serverid=myserverid;cmd=user-sync 3 1441207511
p4_cmd_cumulative_seconds;serverid=myserverid;cmd=user-sync 0.096 1441207511
p4_cmd_program_counter;serverid=myserverid;program=p4/2016.2/LINUX26X86_64/1598668 3 1441207511
p4_cmd_program_cumulative_seconds;serverid=myserverid;program=p4/2016.2/LINUX26X86_64/1598668 0.096 1441207511
p4_cmd_running;serverid=myserverid 0 1441207450
p4_cmd_running;serverid=myserverid 0 1441207511
p4_cmd_running;serverid=myserverid 1 1441207511
p4_cmd_cpu_system_cumulative_seconds;serverid=myserverid;cmd=user-sync 0.000 1441207511
p4_cmd_cpu_user_cumulative_seconds;serverid=myserverid;cmd=user-sync 0.000 1441207511
p4_prom_cmds_pending;serverid=myserverid 0 1441207450
p4_prom_cmds_pending;serverid=myserverid 0 1441207511
p4_prom_cmds_pending;serverid=myserverid 0 1441207511
p4_prom_cmds_processed;serverid=myserverid 0 1441207450
p4_prom_cmds_processed;serverid=myserverid 0 1441207511
p4_prom_cmds_processed;serverid=myserverid 3 1441207511
p4_prom_log_lines_read;serverid=myserverid 10 1441207450
p4_prom_log_lines_read;serverid=myserverid 17 1441207511
p4_prom_log_lines_read;serverid=myserverid 22 1441207511
p4_sync_bytes_added;serverid=myserverid 0 1441207450
p4_sync_bytes_added;serverid=myserverid 0 1441207511
p4_sync_bytes_added;serverid=myserverid 0 1441207511
p4_sync_bytes_updated;serverid=myserverid 0 1441207450
p4_sync_bytes_updated;serverid=myserverid 0 1441207511
p4_sync_bytes_updated;serverid=myserverid 0 1441207511
p4_sync_files_added;serverid=myserverid 0 1441207450
p4_sync_files_added;serverid=myserverid 0 1441207511
p4_sync_files_added;serverid=myserverid 0 1441207511
p4_sync_files_deleted;serverid=myserverid 0 1441207450
p4_sync_files_deleted;serverid=myserverid 0 1441207511
p4_sync_files_deleted;serverid=myserverid 0 1441207511
p4_sync_files_updated;serverid=myserverid 0 1441207450
p4_sync_files_updated;serverid=myserverid 0 1441207511
p4_sync_files_updated;serverid=myserverid 0 1441207511`, -1)
	compareOutput(t, expected, output)
}

func TestP4PromMultiCmds(t *testing.T) {
	cfg := &Config{
		ServerID:         "myserverid",
		UpdateInterval:   10 * time.Millisecond,
		OutputCmdsByUser: true}
	input := `
Perforce server info:
	2017/12/07 15:00:21 pid 148469 fred@LONWS 10.40.16.14/10.40.48.29 [3DSMax/1.0.0.0] 'user-change -i' trigger swarm.changesave
lapse .044s
Perforce server info:
	2017/12/07 15:00:21 pid 148469 completed .413s 7+4us 0+584io 0+0net 4580k 0pf
Perforce server info:
	2017/12/07 15:00:21 pid 148469 fred@LONWS 10.40.16.14/10.40.48.29 [3DSMax/1.0.0.0] 'user-change -i'
--- lapse .413s
--- usage 10+11us 12+13io 14+15net 4088k 22pf
--- rpc msgs/size in+out 20+21/22mb+23mb himarks 318788/318789 snd/rcv .001s/.002s
--- db.counters
---   pages in+out+cached 6+3+2
---   locks read/write 0/2 rows get+pos+scan put+del 2+0+0 1+0

Perforce server info:
	2018/06/10 23:30:08 pid 25568 fred@lon_ws 10.1.2.3 [p4/2016.2/LINUX26X86_64/1598668] 'dm-CommitSubmit'

Perforce server info:
	2018/06/10 23:30:08 pid 25568 fred@lon_ws 10.1.2.3 [p4/2016.2/LINUX26X86_64/1598668] 'dm-CommitSubmit'
--- meta/commit(W)
---   total lock wait+held read/write 0ms+0ms/0ms+795ms

Perforce server info:
	2018/06/10 23:30:08 pid 25568 fred@lon_ws 10.1.2.3 [p4/2016.2/LINUX26X86_64/1598668] 'dm-CommitSubmit'
--- clients/MCM_client_184%2E51%2E33%2E29_prod_prefix1(W)
---   total lock wait+held read/write 0ms+0ms/0ms+1367ms

Perforce server info:
	2018/06/10 23:30:09 pid 25568 completed 1.38s 34+61us 59680+59904io 0+0net 127728k 1pf
Perforce server info:
	2018/06/10 23:30:08 pid 25568 fred@lon_ws 10.1.2.3 [p4/2016.2/LINUX26X86_64/1598668] 'dm-CommitSubmit'
--- db.integed
---   total lock wait+held read/write 12ms+22ms/24ms+795ms
--- db.archmap
---   total lock wait+held read/write 32ms+33ms/34ms+780ms
`
	// cmdTime1, _ := time.Parse(p4timeformat, "2017/12/07 15:00:21")
	cmdTime2, _ := time.Parse(p4timeformat, "2018/06/10 23:30:09")
	historical := false
	output := basicTest(t, cfg, input, historical)

	assert.Equal(t, 38, len(output))
	expected := eol.Split(`p4_cmd_counter{serverid="myserverid",cmd="dm-CommitSubmit"} 1
p4_cmd_counter{serverid="myserverid",cmd="user-change"} 1
p4_cmd_cumulative_seconds{serverid="myserverid",cmd="dm-CommitSubmit"} 1.380
p4_cmd_cumulative_seconds{serverid="myserverid",cmd="user-change"} 0.413
p4_cmd_program_counter{serverid="myserverid",program="3DSMax/1.0.0.0"} 1
p4_cmd_program_counter{serverid="myserverid",program="p4/2016.2/LINUX26X86_64/1598668"} 1
p4_cmd_program_cumulative_seconds{serverid="myserverid",program="3DSMax/1.0.0.0"} 0.413
p4_cmd_program_cumulative_seconds{serverid="myserverid",program="p4/2016.2/LINUX26X86_64/1598668"} 1.380
p4_cmd_replica_counter{serverid="myserverid",replica="10.40.16.14"} 1
p4_cmd_replica_cumulative_seconds{serverid="myserverid",replica="10.40.16.14"} 0.413
p4_cmd_running{serverid="myserverid"} 1
p4_cmd_user_counter{serverid="myserverid",user="fred"} 2
p4_cmd_cpu_system_cumulative_seconds{serverid="myserverid",cmd="dm-CommitSubmit"} 0.061
p4_cmd_cpu_system_cumulative_seconds{serverid="myserverid",cmd="user-change"} 0.011
p4_cmd_cpu_user_cumulative_seconds{serverid="myserverid",cmd="dm-CommitSubmit"} 0.034
p4_cmd_cpu_user_cumulative_seconds{serverid="myserverid",cmd="user-change"} 0.010
p4_cmd_user_cumulative_seconds{serverid="myserverid",user="fred"} 1.793
p4_prom_cmds_pending{serverid="myserverid"} 0
p4_prom_cmds_processed{serverid="myserverid"} 2
p4_prom_log_lines_read{serverid="myserverid"} 37
p4_sync_bytes_added{serverid="myserverid"} 0
p4_sync_bytes_updated{serverid="myserverid"} 0
p4_sync_files_added{serverid="myserverid"} 0
p4_sync_files_deleted{serverid="myserverid"} 0
p4_sync_files_updated{serverid="myserverid"} 0
p4_total_read_held_seconds{serverid="myserverid",table="archmap"} 0.033
p4_total_read_held_seconds{serverid="myserverid",table="counters"} 0.000
p4_total_read_held_seconds{serverid="myserverid",table="integed"} 0.022
p4_total_read_wait_seconds{serverid="myserverid",table="archmap"} 0.032
p4_total_read_wait_seconds{serverid="myserverid",table="counters"} 0.000
p4_total_read_wait_seconds{serverid="myserverid",table="integed"} 0.012
p4_total_trigger_lapse_seconds{serverid="myserverid",trigger="swarm.changesave"} 0.044
p4_total_write_held_seconds{serverid="myserverid",table="archmap"} 0.780
p4_total_write_held_seconds{serverid="myserverid",table="counters"} 0.000
p4_total_write_held_seconds{serverid="myserverid",table="integed"} 0.795
p4_total_write_wait_seconds{serverid="myserverid",table="archmap"} 0.034
p4_total_write_wait_seconds{serverid="myserverid",table="counters"} 0.000
p4_total_write_wait_seconds{serverid="myserverid",table="integed"} 0.024`, -1)
	compareOutput(t, expected, output)

	historical = true
	output = basicTest(t, cfg, input, historical)

	assert.Equal(t, 56, len(output))
	// Cross check appropriate time is being produced for historical runs
	// assert.Contains(t, output[0], fmt.Sprintf("%d", cmdTime1.Unix()))
	assert.Contains(t, output[len(output)-1], fmt.Sprintf("%d", cmdTime2.Unix()))
	expected = eol.Split(`p4_cmd_counter;serverid=myserverid;cmd=dm-CommitSubmit 1 1528673409
p4_cmd_counter;serverid=myserverid;cmd=user-change 1 1528673409
p4_cmd_cumulative_seconds;serverid=myserverid;cmd=dm-CommitSubmit 1.380 1528673409
p4_cmd_cumulative_seconds;serverid=myserverid;cmd=user-change 0.413 1528673409
p4_cmd_program_counter;serverid=myserverid;program=3DSMax/1.0.0.0 1 1528673409
p4_cmd_program_counter;serverid=myserverid;program=p4/2016.2/LINUX26X86_64/1598668 1 1528673409
p4_cmd_program_cumulative_seconds;serverid=myserverid;program=3DSMax/1.0.0.0 0.413 1528673409
p4_cmd_program_cumulative_seconds;serverid=myserverid;program=p4/2016.2/LINUX26X86_64/1598668 1.380 1528673409
p4_cmd_replica_counter;serverid=myserverid;replica=10.40.16.14 1 1528673409
p4_cmd_replica_cumulative_seconds;serverid=myserverid;replica=10.40.16.14 0.413 1528673409
p4_cmd_running;serverid=myserverid 0 1528673408
p4_cmd_running;serverid=myserverid 0 1528673409
p4_cmd_running;serverid=myserverid 1 1528673409
p4_cmd_user_counter;serverid=myserverid;user=fred 2 1528673409
p4_cmd_cpu_system_cumulative_seconds;serverid=myserverid;cmd=dm-CommitSubmit 0.061 1528673409
p4_cmd_cpu_system_cumulative_seconds;serverid=myserverid;cmd=user-change 0.011 1528673409
p4_cmd_cpu_user_cumulative_seconds;serverid=myserverid;cmd=dm-CommitSubmit 0.034 1528673409
p4_cmd_cpu_user_cumulative_seconds;serverid=myserverid;cmd=user-change 0.010 1528673409
p4_cmd_user_cumulative_seconds;serverid=myserverid;user=fred 1.793 1528673409
p4_prom_cmds_pending;serverid=myserverid 0 1528673408
p4_prom_cmds_pending;serverid=myserverid 0 1528673409
p4_prom_cmds_pending;serverid=myserverid 0 1528673409
p4_prom_cmds_processed;serverid=myserverid 0 1528673408
p4_prom_cmds_processed;serverid=myserverid 0 1528673409
p4_prom_cmds_processed;serverid=myserverid 2 1528673409
p4_prom_log_lines_read;serverid=myserverid 17 1528673408
p4_prom_log_lines_read;serverid=myserverid 30 1528673409
p4_prom_log_lines_read;serverid=myserverid 37 1528673409
p4_sync_bytes_added;serverid=myserverid 0 1528673408
p4_sync_bytes_added;serverid=myserverid 0 1528673409
p4_sync_bytes_added;serverid=myserverid 0 1528673409
p4_sync_bytes_updated;serverid=myserverid 0 1528673408
p4_sync_bytes_updated;serverid=myserverid 0 1528673409
p4_sync_bytes_updated;serverid=myserverid 0 1528673409
p4_sync_files_added;serverid=myserverid 0 1528673408
p4_sync_files_added;serverid=myserverid 0 1528673409
p4_sync_files_added;serverid=myserverid 0 1528673409
p4_sync_files_deleted;serverid=myserverid 0 1528673408
p4_sync_files_deleted;serverid=myserverid 0 1528673409
p4_sync_files_deleted;serverid=myserverid 0 1528673409
p4_sync_files_updated;serverid=myserverid 0 1528673408
p4_sync_files_updated;serverid=myserverid 0 1528673409
p4_sync_files_updated;serverid=myserverid 0 1528673409
p4_total_read_held_seconds;serverid=myserverid;table=archmap 0.033 1528673409
p4_total_read_held_seconds;serverid=myserverid;table=counters 0.000 1528673409
p4_total_read_held_seconds;serverid=myserverid;table=integed 0.022 1528673409
p4_total_read_wait_seconds;serverid=myserverid;table=archmap 0.032 1528673409
p4_total_read_wait_seconds;serverid=myserverid;table=counters 0.000 1528673409
p4_total_read_wait_seconds;serverid=myserverid;table=integed 0.012 1528673409
p4_total_trigger_lapse_seconds;serverid=myserverid;trigger=swarm.changesave 0.044 1528673409
p4_total_write_held_seconds;serverid=myserverid;table=archmap 0.780 1528673409
p4_total_write_held_seconds;serverid=myserverid;table=counters 0.000 1528673409
p4_total_write_held_seconds;serverid=myserverid;table=integed 0.795 1528673409
p4_total_write_wait_seconds;serverid=myserverid;table=archmap 0.034 1528673409
p4_total_write_wait_seconds;serverid=myserverid;table=counters 0.000 1528673409
p4_total_write_wait_seconds;serverid=myserverid;table=integed 0.024 1528673409`, -1)
	compareOutput(t, expected, output)

}

var multiUserInput = `
Perforce server info:
	2015/09/02 15:23:09 pid 1616 robert@robert-test 127.0.0.1 [p4/2016.2/LINUX26X86_64/1598668] 'user-fstat //some/file'
Perforce server info:
	2015/09/02 15:23:09 pid 1616 completed .011s

Perforce server info:
	2015/09/02 15:23:10 pid 1616 ROBERT@robert-test 127.0.0.1 [p4/2016.2/LINUX26X86_64/1598668] 'user-fstat //some/file'
Perforce server info:
	2015/09/02 15:23:10 pid 1616 completed .011s
`
var multiUserExpected = eol.Split(`p4_cmd_counter{serverid="myserverid",cmd="user-fstat"} 2
p4_cmd_cumulative_seconds{serverid="myserverid",cmd="user-fstat"} 0.022
p4_cmd_program_counter{serverid="myserverid",program="p4/2016.2/LINUX26X86_64/1598668"} 2
p4_cmd_program_cumulative_seconds{serverid="myserverid",program="p4/2016.2/LINUX26X86_64/1598668"} 0.022
p4_cmd_running{serverid="myserverid"} 1
p4_cmd_cpu_system_cumulative_seconds{serverid="myserverid",cmd="user-fstat"} 0.000
p4_cmd_cpu_user_cumulative_seconds{serverid="myserverid",cmd="user-fstat"} 0.000
p4_prom_cmds_pending{serverid="myserverid"} 0
p4_prom_cmds_processed{serverid="myserverid"} 2
p4_prom_log_lines_read{serverid="myserverid"} 11
p4_sync_bytes_added{serverid="myserverid"} 0
p4_sync_bytes_updated{serverid="myserverid"} 0
p4_sync_files_added{serverid="myserverid"} 0
p4_sync_files_deleted{serverid="myserverid"} 0
p4_sync_files_updated{serverid="myserverid"} 0`, -1)

func TestP4PromBasicMultiUserCaseSensitive(t *testing.T) {
	// Case sensitive/insensitive user
	cfg := &Config{
		ServerID:            "myserverid",
		UpdateInterval:      10 * time.Millisecond,
		OutputCmdsByUser:    true,
		CaseSensitiveServer: true}
	output := basicTest(t, cfg, multiUserInput, false)
	assert.Equal(t, 19, len(output))
	expected := eol.Split(`p4_cmd_user_counter{serverid="myserverid",user="ROBERT"} 1
p4_cmd_user_counter{serverid="myserverid",user="robert"} 1
p4_cmd_user_cumulative_seconds{serverid="myserverid",user="ROBERT"} 0.011
p4_cmd_user_cumulative_seconds{serverid="myserverid",user="robert"} 0.011`, -1)
	for _, l := range multiUserExpected {
		expected = append(expected, l)
	}
	compareOutput(t, expected, output)

}

func TestP4PromBasicMultiUserCaseInsensitive(t *testing.T) {
	// Case sensitive/insensitive user
	cfg := &Config{
		ServerID:            "myserverid",
		UpdateInterval:      10 * time.Millisecond,
		OutputCmdsByUser:    true,
		CaseSensitiveServer: false}
	output := basicTest(t, cfg, multiUserInput, false)
	assert.Equal(t, 17, len(output))
	expected := eol.Split(`p4_cmd_user_counter{serverid="myserverid",user="robert"} 2
p4_cmd_user_cumulative_seconds{serverid="myserverid",user="robert"} 0.022`, -1)
	for _, l := range multiUserExpected {
		expected = append(expected, l)
	}
	compareOutput(t, expected, output)
}

func TestP4PromBasicMultiUserDetail(t *testing.T) {
	// Case sensitive/insensitive user
	cfg := &Config{
		ServerID:              "myserverid",
		UpdateInterval:        10 * time.Millisecond,
		OutputCmdsByUser:      true,
		CaseSensitiveServer:   true,
		OutputCmdsByUserRegex: ".*",
	}
	output := basicTest(t, cfg, multiUserInput, false)
	assert.Equal(t, 23, len(output))
	expected := eol.Split(`p4_cmd_user_counter{serverid="myserverid",user="ROBERT"} 1
p4_cmd_user_counter{serverid="myserverid",user="robert"} 1
p4_cmd_user_detail_counter{serverid="myserverid",user="ROBERT",cmd="user-fstat"} 1
p4_cmd_user_detail_counter{serverid="myserverid",user="robert",cmd="user-fstat"} 1
p4_cmd_user_cumulative_seconds{serverid="myserverid",user="ROBERT"} 0.011
p4_cmd_user_cumulative_seconds{serverid="myserverid",user="robert"} 0.011
p4_cmd_user_detail_cumulative_seconds{serverid="myserverid",user="ROBERT",cmd="user-fstat"} 0.011
p4_cmd_user_detail_cumulative_seconds{serverid="myserverid",user="robert",cmd="user-fstat"} 0.011`, -1)
	for _, l := range multiUserExpected {
		expected = append(expected, l)
	}
	compareOutput(t, expected, output)

}

var multiIPInput = `
Perforce server info:
	2015/09/02 15:23:09 pid 1616 robert@robert-test 10.1.2.3 [p4/2016.2/LINUX26X86_64/1598668] 'user-fstat //some/file'
Perforce server info:
	2015/09/02 15:23:09 pid 1616 completed .011s

Perforce server info:
	2015/09/02 15:23:10 pid 1616 ROBERT@robert-test 127.0.0.1/10.10.4.5 [p4/2016.2/LINUX26X86_64/1598668 (brokered)] 'user-fstat //some/file'
Perforce server info:
	2015/09/02 15:23:10 pid 1616 completed .011s
`
var multiIPExpected = eol.Split(`p4_cmd_counter{serverid="myserverid",cmd="user-fstat"} 2
p4_cmd_cumulative_seconds{serverid="myserverid",cmd="user-fstat"} 0.022
p4_cmd_program_counter{serverid="myserverid",program="p4/2016.2/LINUX26X86_64/1598668"} 2
p4_cmd_program_cumulative_seconds{serverid="myserverid",program="p4/2016.2/LINUX26X86_64/1598668"} 0.022
p4_cmd_replica_counter{serverid="myserverid",replica="127.0.0.1"} 1
p4_cmd_replica_cumulative_seconds{serverid="myserverid",replica="127.0.0.1"} 0.011
p4_cmd_running{serverid="myserverid"} 1
p4_cmd_cpu_system_cumulative_seconds{serverid="myserverid",cmd="user-fstat"} 0.000
p4_cmd_cpu_user_cumulative_seconds{serverid="myserverid",cmd="user-fstat"} 0.000
p4_prom_cmds_pending{serverid="myserverid"} 0
p4_prom_cmds_processed{serverid="myserverid"} 2
p4_prom_log_lines_read{serverid="myserverid"} 11
p4_sync_bytes_added{serverid="myserverid"} 0
p4_sync_bytes_updated{serverid="myserverid"} 0
p4_sync_files_added{serverid="myserverid"} 0
p4_sync_files_deleted{serverid="myserverid"} 0
p4_sync_files_updated{serverid="myserverid"} 0`, -1)

func TestP4PromBasicMultiIPFalse(t *testing.T) {
	// No output by IP
	cfg := &Config{
		ServerID:       "myserverid",
		UpdateInterval: 10 * time.Millisecond,
		OutputCmdsByIP: false}
	output := basicTest(t, cfg, multiIPInput, false)
	assert.Equal(t, 17, len(output))
	compareOutput(t, multiIPExpected, output)
}

func TestP4PromBasicMultiIPTrue(t *testing.T) {
	// Output by IP - so extra metrics
	cfg := &Config{
		ServerID:       "myserverid",
		UpdateInterval: 10 * time.Millisecond,
		OutputCmdsByIP: true}
	output := basicTest(t, cfg, multiIPInput, false)
	assert.Equal(t, 21, len(output))

	expected := eol.Split(`p4_cmd_ip_counter{serverid="myserverid",ip="10.1.2.3"} 1
p4_cmd_ip_counter{serverid="myserverid",ip="10.10.4.5"} 1
p4_cmd_ip_cumulative_seconds{serverid="myserverid",ip="10.1.2.3"} 0.011
p4_cmd_ip_cumulative_seconds{serverid="myserverid",ip="10.10.4.5"} 0.011`, -1)
	for _, l := range multiIPExpected {
		expected = append(expected, l)
	}

	compareOutput(t, expected, output)
}
