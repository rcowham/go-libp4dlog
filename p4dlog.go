/*
Package p4dlog parses Perforce text logs (not structured logs).

It assumes you have set configurable server=3 (or greater)
You may also have decided to set track=1 to get more detailed usage of
access to different tables.

See p4dlog_test.go for examples of log entries.

*/
package p4dlog

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"time"
)

// GO standard reference value/format: Mon Jan 2 15:04:05 -0700 MST 2006
const p4timeformat = "2006/01/02 15:04:05"

var reCmd = regexp.MustCompile(`^\t(\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d) pid (\d+) ([^ @]*)@([^ ]*) ([^ ]*) \[(.*?)\] \'([\w-]+) (.*)\'.*`)
var reCmdNoarg = regexp.MustCompile(`^\t(\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d) pid (\d+) ([^ @]*)@([^ ]*) ([^ ]*) \[(.*?)\] \'([\w-]+)\'.*`)
var reCompute = regexp.MustCompile(`^\t(\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d) pid (\d+) compute end ([0-9]+|[0-9]+\.[0-9]+|\.[0-9]+)s.*`)
var reCompleted = regexp.MustCompile(`^\t(\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d) pid (\d+) completed ([0-9]+|[0-9]+\.[0-9]+|\.[0-9]+)s.*`)
var reJSONCmdargs = regexp.MustCompile(`^(.*) \{.*\}$`)

var infoBlock = []byte("Perforce server info:")

func toInt64(buf []byte) (n int64) {
	for _, v := range buf {
		n = n*10 + int64(v-'0')
	}
	return
}

// P4dParseOptions - Options for parsing - mainly for command line usage
type P4dParseOptions struct {
	File      string
	testInput string // For testing only
}

// Block is a block of lines parsed from a file
type Block struct {
	lineNo int64
	lines  [][]byte
}

func (block *Block) addLine(line []byte, lineNo int64) {
	// Need to copy original line
	newLine := make([]byte, len(line))
	copy(newLine, line)
	block.lines = append(block.lines, newLine)
	if block.lineNo == 0 {
		block.lineNo = lineNo
	}
}

// Command is a command found in the block
type Command struct {
	ProcessKey     string    `json:"processKey"`
	Cmd            []byte    `json:"cmd"`
	Pid            int64     `json:"pid"`
	LineNo         int64     `json:"lineNo"`
	User           []byte    `json:"user"`
	Workspace      []byte    `json:"workspace"`
	StartTime      time.Time `json:"startTime"`
	EndTime        time.Time `json:"endTime"`
	ComputeLapse   float32   `json:"computeLapse"`
	CompletedLapse float32   `json:"completedLapse"`
	IP             []byte    `json:"ip"`
	App            []byte    `json:"app"`
	Args           []byte    `json:"args"`
	Running        int64     `json:"running"`
	UCpu           int64     `json:"uCpu"`
	SCpu           int64     `json:"sCpu"`
	DiskIn         int64     `json:"diskIn"`
	DiskOut        int64     `json:"diskOut"`
	IpcIn          int64     `json:"ipcIn"`
	IpcOut         int64     `json:"ipcOut"`
	MaxRss         int64     `json:"maxRss"`
	PageFaults     int64     `json:"pageFaults"`
	RPCMsgsIn      int64     `json:"rpcMsgsIn"`
	RPCMsgsOut     int64     `json:"rpcMsgsOut"`
	RPCSizeIn      int64     `json:"rpcSizeIn"`
	RPCSizeOut     int64     `json:"rpcSizeOut"`
	RPCHimarkFwd   int64     `json:"rpcHimarkFwd"`
	RPCHimarkRev   int64     `json:"rpcHimarkRev"`
	RPCSnd         float32   `json:"rpcSnd"`
	RPCRcv         float32   `json:"rpcRcv"`
	Tables         map[string]*Table
	duplicateKey   bool
	completed      bool
	hasTrackInfo   bool
}

// Duration is a
type Duration time.Duration

// MarshalJSON serializes durations as seconds
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).Seconds() * 1000)
}

// Table stores track information per table (part of Command)
type Table struct {
	TableName      string   `json:"tableName"`
	PagesIn        int64    `json:"pagesIn"`
	PagesOut       int64    `json:"pagesOut"`
	PagesCached    int64    `json:"pagesCached"`
	ReadLocks      int64    `json:"readLocks"`
	WriteLocks     int64    `json:"writeLocks"`
	GetRows        int64    `json:"getRows"`
	PosRows        int64    `json:"posRows"`
	ScanRows       int64    `json:"scanRows"`
	PutRows        int64    `json:"putRows"`
	DelRows        int64    `json:"delRows"`
	TotalReadWait  Duration `json:"totalReadWait"`
	TotalReadHeld  Duration `json:"totalReadHeld"`
	TotalWriteWait Duration `json:"totalWriteWait"`
	TotalWriteHeld Duration `json:"totalWriteHeld"`
	MaxReadWait    Duration `json:"maxReadWait"`
	MaxReadHeld    Duration `json:"maxReadHeld"`
	MaxWriteWait   Duration `json:"maxWriteWait"`
	MaxWriteHeld   Duration `json:"maxWriteHeld"`
	PeekCount      int64    `json:"peekCount"`
	TotalPeekWait  Duration `json:"totalPeekWait"`
	TotalPeekHeld  Duration `json:"totalPeekHeld"`
	MaxPeekWait    Duration `json:"maxPeekWait"`
	MaxPeekHeld    Duration `json:"maxPeekHeld"`
	TriggerLapse   float32  `json:"triggerLapse"`
}

func parseMillisecond(value []byte) Duration {
	asInt, err := strconv.ParseInt(string(value), 10, 64)
	if err != nil {
		return 0
	}
	return Duration(time.Duration(asInt) * time.Millisecond)
}

func (t *Table) setPages(pagesIn, pagesOut, pagesCached []byte) {
	t.PagesIn, _ = strconv.ParseInt(string(pagesIn), 10, 64)
	t.PagesOut, _ = strconv.ParseInt(string(pagesOut), 10, 64)
	t.PagesCached, _ = strconv.ParseInt(string(pagesCached), 10, 64)
}

func (t *Table) setLocksRows(readLocks, writeLocks, getRows, posRows,
	scanRows, putRows, delRows []byte) {
	t.ReadLocks, _ = strconv.ParseInt(string(readLocks), 10, 64)
	t.WriteLocks, _ = strconv.ParseInt(string(writeLocks), 10, 64)
	t.GetRows, _ = strconv.ParseInt(string(getRows), 10, 64)
	t.PosRows, _ = strconv.ParseInt(string(posRows), 10, 64)
	t.ScanRows, _ = strconv.ParseInt(string(scanRows), 10, 64)
	t.PutRows, _ = strconv.ParseInt(string(putRows), 10, 64)
	t.DelRows, _ = strconv.ParseInt(string(delRows), 10, 64)
}

func (t *Table) setTotalLock(totalReadWait, totalReadHeld, totalWriteWait, totalWriteHeld []byte) {
	t.TotalReadWait = parseMillisecond(totalReadWait)
	t.TotalReadHeld = parseMillisecond(totalReadHeld)
	t.TotalWriteWait = parseMillisecond(totalWriteWait)
	t.TotalWriteHeld = parseMillisecond(totalWriteHeld)
}

func (t *Table) setMaxLock(maxReadWait, maxReadHeld, maxWriteWait, maxWriteHeld []byte) {
	t.MaxReadWait = parseMillisecond(maxReadWait)
	t.MaxReadHeld = parseMillisecond(maxReadHeld)
	t.MaxWriteWait = parseMillisecond(maxWriteWait)
	t.MaxWriteHeld = parseMillisecond(maxWriteHeld)
}

func (t *Table) setPeek(peekCount, totalPeekWait, totalPeekHeld, maxPeekWait, maxPeekHeld []byte) {
	t.PeekCount, _ = strconv.ParseInt(string(peekCount), 10, 64)
	t.TotalPeekWait = parseMillisecond(totalPeekWait)
	t.TotalPeekHeld = parseMillisecond(totalPeekHeld)
	t.MaxPeekWait = parseMillisecond(maxPeekWait)
	t.MaxPeekHeld = parseMillisecond(maxPeekHeld)
}

func newCommand() *Command {
	c := new(Command)
	c.Tables = make(map[string]*Table, 0)
	return c
}

func newTable(name string) *Table {
	t := new(Table)
	t.TableName = name
	return t
}

func (c *Command) getKey() string {
	if c.duplicateKey {
		return fmt.Sprintf("%s.%d", c.ProcessKey, c.LineNo)
	}
	return c.ProcessKey
}

func (c *Command) String() string {
	j, _ := json.Marshal(c)
	return string(j)
}

func (c *Command) setStartTime(t []byte) {
	c.StartTime, _ = time.Parse(p4timeformat, string(t))
}

func (c *Command) setEndTime(t []byte) {
	c.EndTime, _ = time.Parse(p4timeformat, string(t))
}

func (c *Command) setUsage(uCpu, sCpu, diskIn, diskOut, ipcIn, ipcOut, maxRss, pageFaults []byte) {
	c.UCpu, _ = strconv.ParseInt(string(uCpu), 10, 64)
	c.SCpu, _ = strconv.ParseInt(string(sCpu), 10, 64)
	c.DiskIn, _ = strconv.ParseInt(string(diskIn), 10, 64)
	c.DiskOut, _ = strconv.ParseInt(string(diskOut), 10, 64)
	c.IpcIn, _ = strconv.ParseInt(string(ipcIn), 10, 64)
	c.IpcOut, _ = strconv.ParseInt(string(ipcOut), 10, 64)
	c.MaxRss, _ = strconv.ParseInt(string(maxRss), 10, 64)
	c.PageFaults, _ = strconv.ParseInt(string(pageFaults), 10, 64)
}

func (c *Command) setRPC(rpcMsgsIn, rpcMsgsOut, rpcSizeIn, rpcSizeOut, rpcHimarkFwd, rpcHimarkRev, rpcSnd, rpcRcv []byte) {
	c.RPCMsgsIn, _ = strconv.ParseInt(string(rpcMsgsIn), 10, 64)
	c.RPCMsgsOut, _ = strconv.ParseInt(string(rpcMsgsOut), 10, 64)
	c.RPCSizeIn, _ = strconv.ParseInt(string(rpcSizeIn), 10, 64)
	c.RPCSizeOut, _ = strconv.ParseInt(string(rpcSizeOut), 10, 64)
	c.RPCHimarkFwd, _ = strconv.ParseInt(string(rpcHimarkFwd), 10, 64)
	c.RPCHimarkRev, _ = strconv.ParseInt(string(rpcHimarkRev), 10, 64)
	if rpcSnd != nil {
		f, _ := strconv.ParseFloat(string(rpcSnd), 32)
		c.RPCSnd = float32(f)
	}
	if rpcRcv != nil {
		f, _ := strconv.ParseFloat(string(rpcRcv), 32)
		c.RPCRcv = float32(f)
	}
}

// MarshalJSON - handle time formatting
func (c *Command) MarshalJSON() ([]byte, error) {
	tables := make([]Table, len(c.Tables))
	i := 0
	for _, v := range c.Tables {
		tables[i] = *v
		i++
	}
	sort.Slice(tables[:], func(i, j int) bool {
		return tables[i].TableName < tables[j].TableName
	})
	return json.Marshal(&struct {
		ProcessKey     string  `json:"processKey"`
		Cmd            string  `json:"cmd"`
		Pid            int64   `json:"pid"`
		LineNo         int64   `json:"lineNo"`
		User           string  `json:"user"`
		Workspace      string  `json:"workspace"`
		ComputeLapse   float32 `json:"computeLapse"`
		CompletedLapse float32 `json:"completedLapse"`
		IP             string  `json:"ip"`
		App            string  `json:"app"`
		Args           string  `json:"args"`
		StartTime      string  `json:"startTime"`
		EndTime        string  `json:"endTime"`
		Running        int64   `json:"running"`
		UCpu           int64   `json:"uCpu"`
		SCpu           int64   `json:"sCpu"`
		DiskIn         int64   `json:"diskIn"`
		DiskOut        int64   `json:"diskOut"`
		IpcIn          int64   `json:"ipcIn"`
		IpcOut         int64   `json:"ipcOut"`
		MaxRss         int64   `json:"maxRss"`
		PageFaults     int64   `json:"pageFaults"`
		RPCMsgsIn      int64   `json:"rpcMsgsIn"`
		RPCMsgsOut     int64   `json:"rpcMsgsOut"`
		RPCSizeIn      int64   `json:"rpcSizeIn"`
		RPCSizeOut     int64   `json:"rpcSizeOut"`
		RPCHimarkFwd   int64   `json:"rpcHimarkFwd"`
		RPCHimarkRev   int64   `json:"rpcHimarkRev"`
		RPCSnd         float32 `json:"rpcSnd"`
		RPCRcv         float32 `json:"rpcRcv"`
		Tables         []Table `json:"tables"`
	}{
		ProcessKey:     c.getKey(),
		Cmd:            string(c.Cmd),
		Pid:            c.Pid,
		LineNo:         c.LineNo,
		User:           string(c.User),
		Workspace:      string(c.Workspace),
		ComputeLapse:   c.ComputeLapse,
		CompletedLapse: c.CompletedLapse,
		IP:             string(c.IP),
		App:            string(c.App),
		Args:           string(c.Args),
		StartTime:      c.StartTime.Format(p4timeformat),
		EndTime:        c.EndTime.Format(p4timeformat),
		Running:        c.Running,
		UCpu:           c.UCpu,
		SCpu:           c.SCpu,
		DiskIn:         c.DiskIn,
		DiskOut:        c.DiskOut,
		IpcIn:          c.IpcIn,
		IpcOut:         c.IpcOut,
		MaxRss:         c.MaxRss,
		PageFaults:     c.PageFaults,
		RPCMsgsIn:      c.RPCMsgsIn,
		RPCMsgsOut:     c.RPCMsgsOut,
		RPCSizeIn:      c.RPCSizeIn,
		RPCSizeOut:     c.RPCSizeOut,
		RPCHimarkFwd:   c.RPCHimarkFwd,
		RPCHimarkRev:   c.RPCHimarkRev,
		RPCSnd:         c.RPCSnd,
		RPCRcv:         c.RPCRcv,
		Tables:         tables,
	})
}

var blankTime time.Time

func (c *Command) updateFrom(other *Command) {
	if other.EndTime != blankTime {
		c.EndTime = other.EndTime
	}
	if other.ComputeLapse > 0 {
		c.ComputeLapse = other.ComputeLapse
	}
	if other.CompletedLapse > 0 {
		c.CompletedLapse = other.CompletedLapse
	}
	if other.UCpu > 0 {
		c.UCpu = other.UCpu
	}
	if other.SCpu > 0 {
		c.SCpu = other.SCpu
	}
	if other.DiskIn > 0 {
		c.DiskIn = other.DiskIn
	}
	if other.DiskOut > 0 {
		c.DiskOut = other.DiskOut
	}
	if other.IpcIn > 0 {
		c.IpcIn = other.IpcIn
	}
	if other.IpcOut > 0 {
		c.IpcOut = other.IpcOut
	}
	if other.MaxRss > 0 {
		c.MaxRss = other.MaxRss
	}
	if other.PageFaults > 0 {
		c.PageFaults = other.PageFaults
	}
	if other.IpcIn > 0 {
		c.IpcIn = other.IpcIn
	}
	if other.RPCMsgsIn > 0 {
		c.RPCMsgsIn = other.RPCMsgsIn
	}
	if other.RPCMsgsOut > 0 {
		c.RPCMsgsOut = other.RPCMsgsOut
	}
	if other.RPCMsgsIn > 0 {
		c.RPCMsgsIn = other.RPCMsgsIn
	}
	if other.RPCSizeIn > 0 {
		c.RPCSizeIn = other.RPCSizeIn
	}
	if other.RPCSizeOut > 0 {
		c.RPCSizeOut = other.RPCSizeOut
	}
	if other.RPCHimarkFwd > 0 {
		c.RPCHimarkFwd = other.RPCHimarkFwd
	}
	if other.RPCHimarkRev > 0 {
		c.RPCHimarkRev = other.RPCHimarkRev
	}
	if other.RPCSnd > 0 {
		c.RPCSnd = other.RPCSnd
	}
	if other.RPCRcv > 0 {
		c.RPCRcv = other.RPCRcv
	}
	if len(other.Tables) > 0 {
		for k, t := range other.Tables {
			c.Tables[k] = t
		}
	}
}

// P4dFileParser - manages state
type P4dFileParser struct {
	lineNo               int64
	cmds                 map[int64]*Command
	cmdchan              chan Command
	currStartTime        time.Time
	timeLastCmdProcessed time.Time
	pidsSeenThisSecond   map[int64]bool
	running              int64
	block                *Block
}

func (fp *P4dFileParser) addCommand(newCmd *Command, hasTrackInfo bool) {
	newCmd.Running = fp.running
	if fp.currStartTime != newCmd.StartTime && newCmd.StartTime.After(fp.currStartTime) {
		fp.currStartTime = newCmd.StartTime
		fp.pidsSeenThisSecond = make(map[int64]bool)
	}
	if cmd, ok := fp.cmds[newCmd.Pid]; ok {
		if cmd.ProcessKey != newCmd.ProcessKey {
			fp.cmdchan <- *cmd
			fp.cmds[newCmd.Pid] = newCmd // Replace previous cmd with same PID
		} else if bytes.Equal(newCmd.Cmd, []byte("rmt-FileFetch")) ||
			bytes.Equal(newCmd.Cmd, []byte("rmt-Journal")) ||
			bytes.Equal(newCmd.Cmd, []byte("pull")) {
			if hasTrackInfo {
				cmd.updateFrom(newCmd)
			} else {
				fp.cmdchan <- *cmd
				newCmd.duplicateKey = true
				fp.cmds[newCmd.Pid] = newCmd // Replace previous cmd with same PID
			}
		} else {
			cmd.updateFrom(newCmd)
		}
		if hasTrackInfo {
			cmd.hasTrackInfo = true
		}
	} else {
		fp.cmds[newCmd.Pid] = newCmd
		if _, ok := fp.pidsSeenThisSecond[newCmd.Pid]; ok {
			newCmd.duplicateKey = true
		}
		fp.pidsSeenThisSecond[newCmd.Pid] = true
		fp.running++
	}
	fp.outputCompletedCommands()
}

var trackStart = []byte("---")
var trackLapse = []byte("--- lapse ")
var trackDB = []byte("--- db.")
var trackMeta = []byte("--- meta")
var trackClients = []byte("--- clients")
var trackChange = []byte("--- change")
var reCmdTrigger = regexp.MustCompile(` trigger ([^ ]+)$`)
var reTriggerLapse = regexp.MustCompile(`^lapse (\d+)s`)
var reTriggerLapse2 = regexp.MustCompile(`^lapse \.(\d+)s`)
var reTrackRPC = regexp.MustCompile(`^--- rpc msgs/size in\+out (\d+)\+(\d+)/(\d+)mb\+(\d+)mb himarks (\d+)/(\d+)`)
var reTrackRPC2 = regexp.MustCompile(`^--- rpc msgs/size in\+out (\d+)\+(\d+)/(\d+)mb\+(\d+)mb himarks (\d+)/(\d+) snd/rcv ([0-9]+|[0-9]+\.[0-9]+|\.[0-9]+)s/([0-9]+|[0-9]+\.[0-9]+|\.[0-9]+)s`)
var reTrackUsage = regexp.MustCompile(`^--- usage (\d+)\+(\d+)us (\d+)\+(\d+)io (\d+)\+(\d+)net (\d+)k (\d+)pf`)
var reTrackPages = regexp.MustCompile(`^---   pages in\+out\+cached (\d+)\+(\d+)\+(\d+)`)
var reTrackLocksRows = regexp.MustCompile(`^---   locks read/write (\d+)/(\d+) rows get\+pos\+scan put\+del (\d+)\+(\d+)\+(\d+) (\d+)\+(\d+)`)
var reTrackTotalLock = regexp.MustCompile(`^---   total lock wait\+held read/write (\d+)ms\+(\d+)ms/(\d+)ms\+(\d+)ms`)
var reTrackPeek = regexp.MustCompile(`^---   peek count (\d+) wait\+held total/max (\d+)ms\+(\d+)ms/(\d+)ms\+(\d+)ms`)
var reTrackMaxLock = regexp.MustCompile(`^---   max lock wait\+held read/write (\d+)ms\+(\d+)ms/(\d+)ms\+(\d+)ms|---   locks wait+held read/write (\d+)ms\+(\d+)ms/(\d+)ms\+(\d+)ms`)

func getTable(cmd *Command, tableName string) *Table {
	if _, ok := cmd.Tables[tableName]; !ok {
		cmd.Tables[tableName] = newTable(tableName)
	}
	return cmd.Tables[tableName]
}

func (fp *P4dFileParser) processTrackRecords(cmd *Command, lines [][]byte) {
	hasTrackInfo := false
	var tableName string
	for _, line := range lines {
		if bytes.Equal(trackLapse, line[:len(trackLapse)]) {
			val := line[len(trackLapse):]
			i := bytes.IndexByte(val, '.')
			j := bytes.IndexByte(val, 's')
			if i >= 0 && j > 0 {
				f, _ := strconv.ParseFloat(string(val[i:j-i]), 32)
				cmd.CompletedLapse = float32(f)
			}
			continue
		}
		if bytes.Equal(trackDB, line[:len(trackDB)]) {
			tableName = string(line[len(trackDB):])
			t := newTable(tableName)
			cmd.Tables[tableName] = t
			hasTrackInfo = true
			continue
		}
		if bytes.Equal(trackMeta, line[:len(trackMeta)]) ||
			bytes.Equal(trackChange, line[:len(trackChange)]) ||
			bytes.Equal(trackClients, line[:len(trackClients)]) {
			// Special tables don't have trackInfo set
			continue
		}
		if !bytes.Equal(trackStart, line[:len(trackStart)]) {
			continue
		}
		m := reTrackUsage.FindSubmatch(line)
		if len(m) > 0 {
			cmd.setUsage(m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8])
			continue
		}
		m = reTrackRPC2.FindSubmatch(line)
		if len(m) > 0 {
			cmd.setRPC(m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8])
			continue
		}
		m = reTrackRPC.FindSubmatch(line)
		if len(m) > 0 {
			cmd.setRPC(m[1], m[2], m[3], m[4], m[5], m[6], nil, nil)
			continue
		}
		m = reTrackPages.FindSubmatch(line)
		if len(m) > 0 {
			t := getTable(cmd, tableName)
			t.setPages(m[1], m[2], m[3])
			continue
		}
		m = reTrackLocksRows.FindSubmatch(line)
		if len(m) > 0 {
			t := getTable(cmd, tableName)
			t.setLocksRows(m[1], m[2], m[3], m[4], m[5], m[6], m[7])
			continue
		}
		m = reTrackTotalLock.FindSubmatch(line)
		if len(m) > 0 {
			t := getTable(cmd, tableName)
			t.setTotalLock(m[1], m[2], m[3], m[4])
			continue
		}
		m = reTrackMaxLock.FindSubmatch(line)
		if len(m) > 0 {
			t := getTable(cmd, tableName)
			t.setMaxLock(m[1], m[2], m[3], m[4])
			continue
		}
		m = reTrackPeek.FindSubmatch(line)
		if len(m) > 0 {
			t := getTable(cmd, tableName)
			t.setPeek(m[1], m[2], m[3], m[4], m[5])
			continue
		}
	}
	cmd.hasTrackInfo = hasTrackInfo
	fp.addCommand(cmd, hasTrackInfo)
}

// Output all completed commands 3 or more seconds ago
func (fp *P4dFileParser) outputCompletedCommands() {
	const timeWindow = 3
	cmdHasBeenProcessed := false
	currTime := time.Now()
	for _, cmd := range fp.cmds {
		completed := false
		if cmd.completed && (cmd.hasTrackInfo || fp.currStartTime.Sub(cmd.EndTime) >= timeWindow*time.Second ||
			(fp.timeLastCmdProcessed != blankTime && currTime.Sub(fp.timeLastCmdProcessed) >= timeWindow*time.Second)) {
			completed = true
		}
		if !completed && (cmd.hasTrackInfo && cmd.EndTime != blankTime &&
			fp.currStartTime.Sub(cmd.EndTime) >= timeWindow*time.Second) {
			completed = true
		}
		if completed {
			cmdHasBeenProcessed = true
			fp.cmdchan <- *cmd
			delete(fp.cmds, cmd.Pid)
			fp.running--
		}
	}
	if cmdHasBeenProcessed || fp.timeLastCmdProcessed == blankTime {
		fp.timeLastCmdProcessed = time.Now()
	}
}

// Processes all remaining commands whether completed or not - intended for use at end
func (fp *P4dFileParser) outputRemainingCommands() {
	for _, cmd := range fp.cmds {
		fp.cmdchan <- *cmd
	}
	fp.cmds = make(map[int64]*Command)
}

func (fp *P4dFileParser) updateComputeTime(pid int64, computeLapse []byte) {
	if cmd, ok := fp.cmds[pid]; ok {
		// sum all compute values for same command
		f, _ := strconv.ParseFloat(string(computeLapse), 32)
		cmd.ComputeLapse = cmd.ComputeLapse + float32(f)
	}

}

func (fp *P4dFileParser) updateCompletionTime(pid int64, endTime []byte, completedLapse []byte) {
	if cmd, ok := fp.cmds[pid]; ok {
		cmd.setEndTime(endTime)
		f, _ := strconv.ParseFloat(string(completedLapse), 32)
		cmd.CompletedLapse = float32(f)
		cmd.completed = true
	} else {

	}
}

func (fp *P4dFileParser) processTriggerLapse(cmd *Command, trigger string, line []byte) {
	// Expects a single line with a lapse statement on it
	var triggerLapse float64
	m := reTriggerLapse.FindSubmatch(line)
	if len(m) > 0 {
		triggerLapse, _ = strconv.ParseFloat(string(m[1]), 32)
	} else {
		m = reTriggerLapse2.FindSubmatch(line)
		if len(m) > 0 {
			s := fmt.Sprintf("0.%s", string(m[1]))
			triggerLapse, _ = strconv.ParseFloat(s, 32)
		}
	}
	if triggerLapse > 0 {
		tableName := fmt.Sprintf("trigger_%s", trigger)
		t := newTable(tableName)
		t.TriggerLapse = float32(triggerLapse)
		cmd.Tables[tableName] = t
	}
}

func (fp *P4dFileParser) processInfoBlock(block *Block) {

	var cmd *Command
	i := 0
	for _, line := range block.lines[1:] {
		i++
		if cmd != nil && bytes.Equal(trackStart, line[:3]) {
			fp.processTrackRecords(cmd, block.lines[i:])
			return // Block has been processed
		}

		m := reCmd.FindSubmatch(line)
		if len(m) == 0 {
			m = reCmdNoarg.FindSubmatch(line)
		}
		if len(m) > 0 {
			cmd = newCommand()
			cmd.LineNo = block.lineNo
			cmd.setStartTime(m[1])
			cmd.Pid = toInt64(m[2])
			cmd.User = m[3]
			cmd.Workspace = m[4]
			cmd.IP = m[5]
			cmd.App = m[6]
			cmd.Cmd = m[7]
			// # following gsub required due to a 2009.2 P4V bug
			// App = match.group(6).replace("\x00", "/")
			if len(m) > 8 {
				cmd.Args = m[8]
				// Strip Swarm/Git Fusion commands with lots of json
				sm := reJSONCmdargs.FindSubmatch(cmd.Args)
				if len(sm) > 0 {
					cmd.Args = sm[1]
				}
			}
			// Detect trigger entries
			trigger := ""
			if i := bytes.Index(line, []byte("' trigger ")); i >= 0 {
				tm := reCmdTrigger.FindSubmatch(line[i:])
				if len(tm) > 0 {
					trigger = string(tm[1])
				}
				line = line[:i+1] // Strip from the line
			}
			h := md5.Sum(line)
			cmd.ProcessKey = hex.EncodeToString(h[:])
			fp.addCommand(cmd, false)
			if len(trigger) > 0 {
				fp.processTriggerLapse(cmd, trigger, block.lines[len(block.lines)-1])
			}
		} else {
			// process completed and computed
			m := reCompleted.FindSubmatch(line)
			if len(m) > 0 {
				endTime := m[1]
				pid := toInt64(m[2])
				completedLapse := m[3]
				fp.updateCompletionTime(pid, endTime, completedLapse)
			} else {
				m := reCompute.FindSubmatch(line)
				if len(m) > 0 {
					pid := toInt64(m[2])
					computeLapse := m[3]
					fp.updateComputeTime(pid, computeLapse)
				}
			}
		}
	}
}

func blankLine(line []byte) bool {
	return len(line) == 0
}

var blockEnds = [][]byte{[]byte("Perforce server info:"), []byte("Perforce server error:"),
	[]byte("locks acquired by blocking after"), []byte("Rpc himark:")}

func blockEnd(line []byte) bool {
	if blankLine(line) {
		return true
	}
	for _, str := range blockEnds {
		if bytes.Equal(line, str) {
			return true
		}
	}
	return false
}

// parseLine - interface for incremental parsing
func (fp *P4dFileParser) parseLine(line []byte) {
	if blockEnd(line) {
		if len(fp.block.lines) > 0 {
			if bytes.Equal(fp.block.lines[0], infoBlock) {
				fp.processInfoBlock(fp.block)
			} else if blankLine(fp.block.lines[0]) {
				fp.outputCompletedCommands()
			}
		}
		fp.block = new(Block)
		fp.block.addLine(line, fp.lineNo)
	} else {
		fp.block.addLine(line, fp.lineNo)
	}
	fp.lineNo++
}

// P4LogParseFinish - interface for incremental parsing
func (fp *P4dFileParser) parseFinish() {
	if len(fp.block.lines) > 0 {
		if bytes.Equal(fp.block.lines[0], infoBlock) {
			fp.processInfoBlock(fp.block)
		}
	}
	fp.outputRemainingCommands()
}

// CmdsPendingCount - count of unmatched commands
func (fp *P4dFileParser) cmdsPendingCount() int {
	return len(fp.cmds)
}

// ParseLog file will read log entries from the provided interface and return a stream
// of
func ParseLog(ctx context.Context, reader io.Reader, tail bool) <-chan Command {
	fp := P4dFileParser{
		cmds:               make(map[int64]*Command),
		pidsSeenThisSecond: make(map[int64]bool),
		block:              new(Block),
		cmdchan:            make(chan Command),
		lineNo:             1,
	}

	scanner := bufio.NewScanner(reader)
	fp.lineNo = 1
	go func() {
		defer close(fp.cmdchan)
		for {
			select {
			case <-time.After(time.Second * 1):
				fp.outputCompletedCommands()
			case <-ctx.Done():
				return
			default:
				lineLimitReached := false
				for linesScanned := 0; scanner.Scan(); linesScanned++ {
					if linesScanned > 50 {
						lineLimitReached = true
						break
					}
					line := scanner.Bytes()
					fp.parseLine(line)
				}
				err := scanner.Err()
				fp.parseFinish()

				if err != nil {
					fmt.Fprintf(os.Stderr, "reading file (line %d): %s\n", fp.lineNo, err)
					return
				}

				if !tail && !lineLimitReached {
					// we hit the end of the file and we're not tailing
					return
				}
			}
		}
	}()
	return fp.cmdchan
}
