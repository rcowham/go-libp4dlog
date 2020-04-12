/*
Metrics module - consume parsed p4d log commands and produce metrics

Primary processing for p4prometheus module.

Also used in log2sql for historical metrics.
*/

package metrics

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	p4dlog "github.com/rcowham/go-libp4dlog"
	"github.com/sirupsen/logrus"
)

// Config for metrics
type Config struct {
	Debug               bool
	ServerID            string
	SDPInstance         string
	UpdateInterval      time.Duration
	OutputCmdsByUser    bool
	CaseSensitiveServer bool
}

// P4DMetrics structure
type P4DMetrics struct {
	config              *Config
	historical          bool
	fp                  *p4dlog.P4dFileParser
	timeLatestStartCmd  time.Time
	latestStartCmdBuf   []byte
	logger              *logrus.Logger
	metricWriter        io.Writer
	cmdCounter          map[string]int32
	cmdCumulative       map[string]float64
	cmdByUserCounter    map[string]int32
	cmdByUserCumulative map[string]float64
	totalReadWait       map[string]float64
	totalReadHeld       map[string]float64
	totalWriteWait      map[string]float64
	totalWriteHeld      map[string]float64
	totalTriggerLapse   map[string]float64
	cmdsProcessed       int64
	linesRead           int64
}

// NewP4DMetricsLogParser - wraps P4dFileParser
func NewP4DMetricsLogParser(config *Config, logger *logrus.Logger, historical bool) (p4m *P4DMetrics) {
	return &P4DMetrics{
		config:              config,
		logger:              logger,
		fp:                  p4dlog.NewP4dFileParser(logger),
		historical:          historical,
		cmdCounter:          make(map[string]int32),
		cmdCumulative:       make(map[string]float64),
		cmdByUserCounter:    make(map[string]int32),
		cmdByUserCumulative: make(map[string]float64),
		totalReadWait:       make(map[string]float64),
		totalReadHeld:       make(map[string]float64),
		totalWriteWait:      make(map[string]float64),
		totalWriteHeld:      make(map[string]float64),
		totalTriggerLapse:   make(map[string]float64),
	}
}

// defines metrics label
type labelStruct struct {
	name  string
	value string
}

func (p4m *P4DMetrics) printMetricHeader(f io.Writer, name string, help string, metricType string) {
	if !p4m.historical {
		fmt.Fprintf(f, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, metricType)
	}
}

// Prometheus format: 	metric_name{label1="val1",label2="val2"}
// Graphite format:  	metric_name;label1=val1;label2=val2
func (p4m *P4DMetrics) formatLabels(mname string, labels []labelStruct) string {
	nonBlankLabels := make([]labelStruct, 0)
	for _, l := range labels {
		if l.value != "" {
			if !p4m.historical {
				l.value = fmt.Sprintf("\"%s\"", l.value)
			}
			nonBlankLabels = append(nonBlankLabels, l)
		}
	}
	vals := make([]string, 0)
	for _, l := range nonBlankLabels {
		vals = append(vals, fmt.Sprintf("%s=%s", l.name, l.value))
	}
	if p4m.historical {
		labelStr := strings.Join(vals, ";")
		return fmt.Sprintf("%s;%s", mname, labelStr)
	}
	labelStr := strings.Join(vals, ",")
	return fmt.Sprintf("%s{%s}", mname, labelStr)
}

func (p4m *P4DMetrics) formatMetric(mname string, labels []labelStruct, metricVal string) string {
	if p4m.historical {
		return fmt.Sprintf("%s %s %d\n", p4m.formatLabels(mname, labels),
			metricVal, p4m.timeLatestStartCmd.Unix())
	}
	return fmt.Sprintf("%s %s\n", p4m.formatLabels(mname, labels), metricVal)
}

// Publish cumulative results - called on a ticker or in historical mode
func (p4m *P4DMetrics) getCumulativeMetrics() string {
	fixedLabels := []labelStruct{{name: "serverid", value: p4m.config.ServerID},
		{name: "sdpinst", value: p4m.config.SDPInstance}}
	metrics := new(bytes.Buffer)
	p4m.logger.Debugf("Writing stats")

	var mname string
	var buf string
	var metricVal string
	mname = "p4_prom_log_lines_read"
	p4m.printMetricHeader(metrics, mname, "A count of log lines read", "counter")
	metricVal = fmt.Sprintf("%d", p4m.linesRead)
	buf = p4m.formatMetric(mname, fixedLabels, metricVal)
	p4m.logger.Debugf(buf)
	fmt.Fprint(metrics, buf)

	mname = "p4_prom_cmds_processed"
	p4m.printMetricHeader(metrics, mname, "A count of all cmds processed", "counter")
	metricVal = fmt.Sprintf("%d", p4m.cmdsProcessed)
	buf = p4m.formatMetric(mname, fixedLabels, metricVal)
	p4m.logger.Debugf(buf)
	fmt.Fprint(metrics, buf)

	mname = "p4_prom_cmds_pending"
	p4m.printMetricHeader(metrics, mname, "A count of all current cmds (not completed)", "gauge")
	metricVal = fmt.Sprintf("%d", p4m.fp.CmdsPendingCount())
	buf = p4m.formatMetric(mname, fixedLabels, metricVal)
	p4m.logger.Debugf(buf)
	fmt.Fprint(metrics, buf)

	mname = "p4_cmd_counter"
	p4m.printMetricHeader(metrics, mname, "A count of completed p4 cmds (by cmd)", "counter")
	for cmd, count := range p4m.cmdCounter {
		metricVal = fmt.Sprintf("%d", count)
		labels := append(fixedLabels, labelStruct{"cmd", cmd})
		buf = p4m.formatMetric(mname, labels, metricVal)
		p4m.logger.Debugf(buf)
		fmt.Fprint(metrics, buf)
	}
	mname = "p4_cmd_cumulative_seconds"
	p4m.printMetricHeader(metrics, mname, "The total in seconds (by cmd)", "counter")
	for cmd, lapse := range p4m.cmdCumulative {
		metricVal = fmt.Sprintf("%0.3f", lapse)
		labels := append(fixedLabels, labelStruct{"cmd", cmd})
		buf = p4m.formatMetric(mname, labels, metricVal)
		p4m.logger.Debugf(buf)
		fmt.Fprint(metrics, buf)
	}
	// For large sites this might not be sensible - so they can turn it off
	if p4m.config.OutputCmdsByUser {
		mname = "p4_cmd_user_counter"
		p4m.printMetricHeader(metrics, mname, "A count of completed p4 cmds (by user)", "counter")
		for user, count := range p4m.cmdByUserCounter {
			metricVal = fmt.Sprintf("%d", count)
			labels := append(fixedLabels, labelStruct{"user", user})
			buf = p4m.formatMetric(mname, labels, metricVal)
			p4m.logger.Debugf(buf)
			fmt.Fprint(metrics, buf)
		}
		mname = "p4_cmd_user_cumulative_seconds"
		p4m.printMetricHeader(metrics, mname, "The total in seconds (by user)", "counter")
		for user, lapse := range p4m.cmdByUserCumulative {
			metricVal = fmt.Sprintf("%0.3f", lapse)
			labels := append(fixedLabels, labelStruct{"user", user})
			buf = p4m.formatMetric(mname, labels, metricVal)
			p4m.logger.Debugf(buf)
			fmt.Fprint(metrics, buf)
		}
	}
	mname = "p4_total_read_wait_seconds"
	p4m.printMetricHeader(metrics, mname,
		"The total waiting for read locks in seconds (by table)", "counter")
	for table, total := range p4m.totalReadWait {
		metricVal = fmt.Sprintf("%0.3f", total)
		labels := append(fixedLabels, labelStruct{"table", table})
		buf = p4m.formatMetric(mname, labels, metricVal)
		p4m.logger.Debugf(buf)
		fmt.Fprint(metrics, buf)
	}
	mname = "p4_total_read_held_seconds"
	p4m.printMetricHeader(metrics, mname,
		"The total read locks held in seconds (by table)", "counter")
	for table, total := range p4m.totalReadHeld {
		metricVal = fmt.Sprintf("%0.3f", total)
		labels := append(fixedLabels, labelStruct{"table", table})
		buf = p4m.formatMetric(mname, labels, metricVal)
		p4m.logger.Debugf(buf)
		fmt.Fprint(metrics, buf)
	}
	mname = "p4_total_write_wait_seconds"
	p4m.printMetricHeader(metrics, mname,
		"The total waiting for write locks in seconds (by table)", "counter")
	for table, total := range p4m.totalWriteWait {
		metricVal = fmt.Sprintf("%0.3f", total)
		labels := append(fixedLabels, labelStruct{"table", table})
		buf = p4m.formatMetric(mname, labels, metricVal)
		p4m.logger.Debugf(buf)
		fmt.Fprint(metrics, buf)
	}
	mname = "p4_total_write_held_seconds"
	p4m.printMetricHeader(metrics, mname,
		"The total write locks held in seconds (by table)", "counter")
	for table, total := range p4m.totalWriteHeld {
		metricVal = fmt.Sprintf("%0.3f", total)
		labels := append(fixedLabels, labelStruct{"table", table})
		buf = p4m.formatMetric(mname, labels, metricVal)
		p4m.logger.Debugf(buf)
		fmt.Fprint(metrics, buf)
	}
	if len(p4m.totalTriggerLapse) > 0 {
		mname = "p4_total_trigger_lapse_seconds"
		p4m.printMetricHeader(metrics, mname,
			"The total lapse time for triggers in seconds (by trigger)", "counter")
		for table, total := range p4m.totalTriggerLapse {
			metricVal = fmt.Sprintf("%0.3f", total)
			labels := append(fixedLabels, labelStruct{"trigger", table})
			buf = p4m.formatMetric(mname, labels, metricVal)
			p4m.logger.Debugf(buf)
			fmt.Fprint(metrics, buf)
		}
	}
	return metrics.String()
}

func (p4m *P4DMetrics) getSeconds(tmap map[string]interface{}, fieldName string) float64 {
	p4m.logger.Debugf("field %s %v, %v\n", fieldName, reflect.TypeOf(tmap[fieldName]), tmap[fieldName])
	if total, ok := tmap[fieldName].(float64); ok {
		return (total)
	}
	return 0
}

func (p4m *P4DMetrics) getMilliseconds(tmap map[string]interface{}, fieldName string) float64 {
	p4m.logger.Debugf("field %s %v, %v\n", fieldName, reflect.TypeOf(tmap[fieldName]), tmap[fieldName])
	if total, ok := tmap[fieldName].(float64); ok {
		return (total / 1000)
	}
	return 0
}

func (p4m *P4DMetrics) publishEvent(cmd p4dlog.Command) {
	// p4m.logger.Debugf("publish cmd: %s\n", cmd.String())

	p4m.cmdCounter[string(cmd.Cmd)]++
	p4m.cmdCumulative[string(cmd.Cmd)] += float64(cmd.CompletedLapse)
	user := string(cmd.User)
	if !p4m.config.CaseSensitiveServer {
		user = strings.ToLower(user)
	}
	p4m.cmdByUserCounter[user]++
	p4m.cmdByUserCumulative[user] += float64(cmd.CompletedLapse)
	const triggerPrefix = "trigger_"

	for _, t := range cmd.Tables {
		if len(t.TableName) > len(triggerPrefix) && t.TableName[:len(triggerPrefix)] == triggerPrefix {
			triggerName := t.TableName[len(triggerPrefix):]
			p4m.totalTriggerLapse[triggerName] += float64(t.TriggerLapse)
		} else {
			p4m.totalReadHeld[t.TableName] += float64(t.TotalReadHeld) / 1000
			p4m.totalReadWait[t.TableName] += float64(t.TotalReadWait) / 1000
			p4m.totalWriteHeld[t.TableName] += float64(t.TotalWriteHeld) / 1000
			p4m.totalWriteWait[t.TableName] += float64(t.TotalWriteWait) / 1000
		}
	}
}

// GO standard reference value/format: Mon Jan 2 15:04:05 -0700 MST 2006
const p4timeformat = "2006/01/02 15:04:05"

// Searches for log lines starting with a <tab>date - assumes increasing dates in log
func (p4m *P4DMetrics) historicalUpdateRequired(line []byte) bool {
	if !p4m.historical {
		return false
	}
	// This next section is more efficient than regex parsing - we return ASAP
	lenPrefix := len("\t2020/03/04 12:13:14")
	if len(line) < lenPrefix {
		return false
	}
	// Check for expected chars at specific points
	if line[0] != '\t' || line[5] != '/' || line[8] != '/' ||
		line[11] != ' ' || line[14] != ':' || line[17] != ':' {
		return false
	}
	// Check for digits
	for _, i := range []int{1, 2, 3, 4, 6, 7, 9, 10, 12, 13, 15, 16, 18, 19} {
		if line[i] < byte('0') || line[i] > byte('9') {
			return false
		}
	}
	if len(p4m.latestStartCmdBuf) == 0 {
		p4m.latestStartCmdBuf = make([]byte, lenPrefix)
		copy(p4m.latestStartCmdBuf, line[:lenPrefix])
		p4m.timeLatestStartCmd, _ = time.Parse(p4timeformat, string(line[1:lenPrefix]))
		return false
	}
	if len(p4m.latestStartCmdBuf) > 0 && bytes.Equal(p4m.latestStartCmdBuf, line[:lenPrefix]) {
		return false
	}
	// Update only if greater (due to log format we do see out of sequence dates with track records)
	if bytes.Compare(line[:lenPrefix], p4m.latestStartCmdBuf) <= 0 {
		return false
	}
	dt, _ := time.Parse(p4timeformat, string(line[1:lenPrefix]))
	if dt.Sub(p4m.timeLatestStartCmd) >= p4m.config.UpdateInterval {
		p4m.timeLatestStartCmd = dt
		copy(p4m.latestStartCmdBuf, line[:lenPrefix])
		return true
	}
	return false
}

// ProcessEvents - main event loop for P4Prometheus - reads lines and outputs metrics
// Wraps p4dlog.LogParser event loop
func (p4m *P4DMetrics) ProcessEvents(ctx context.Context,
	linesInChan <-chan []byte, cmdsOutChan chan<- p4dlog.Command, metricsChan chan<- string) int {
	ticker := time.NewTicker(p4m.config.UpdateInterval)

	if p4m.config.Debug {
		p4m.fp.SetDebugMode()
	}
	fpLines := make(chan []byte, 10000)
	cmdsInChan := make(chan p4dlog.Command, 10000)
	go p4m.fp.LogParser(ctx, fpLines, cmdsInChan)

	for {
		select {
		case <-ctx.Done():
			p4m.logger.Info("Done received")
			close(metricsChan)
			return -1
		case <-ticker.C:
			// Ticker only relevant for live log processing
			p4m.logger.Debugf("publishCumulative")
			if !p4m.historical {
				metricsChan <- p4m.getCumulativeMetrics()
			}
		case cmd, ok := <-cmdsInChan:
			if ok {
				p4m.logger.Debugf("Publishing cmd: %s", cmd.String())
				p4m.cmdsProcessed++
				p4m.publishEvent(cmd)
				cmdsOutChan <- cmd
			} else {
				p4m.logger.Debugf("FP Cmd closed")
				metricsChan <- p4m.getCumulativeMetrics()
				close(metricsChan)
				close(cmdsOutChan)
				return 0
			}
		case line, ok := <-linesInChan:
			if ok {
				p4m.logger.Debugf("Line: %s", line)
				p4m.linesRead++
				// Need to copy original line to avoid overwrites
				newLine := make([]byte, len(line))
				copy(newLine, line)
				fpLines <- newLine
				if p4m.historical && p4m.historicalUpdateRequired(line) {
					metricsChan <- p4m.getCumulativeMetrics()
				}
			} else {
				if fpLines != nil {
					p4m.logger.Debugf("Lines closed")
					close(fpLines)
					fpLines = nil
				}
			}
		}
	}
}
