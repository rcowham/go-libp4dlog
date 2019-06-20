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
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
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
	UCpu           int64     `json:"uCpu"`
	SCpu           int64     `json:"sCpu"`
	DiskIn         int64     `json:"diskIn"`
	DiskOut        int64     `json:"diskOut"`
	IpcIn          int64     `json:"ipcIn"`
	IpcOut         int64     `json:"ipcOut"`
	MaxRss         int64     `json:"maxRss"`
	PageFaults     int64     `json:"pageFaults"`
	RpcMsgsIn      int64     `json:"rpcMsgsIn"`
	RpcMsgsOut     int64     `json:"rpcMsgsOut"`
	RpcSizeIn      int64     `json:"rpcSizeIn"`
	RpcSizeOut     int64     `json:"rpcSizeOut"`
	RpcHimarkFwd   int64     `json:"rpcHimarkFwd"`
	RpcHimarkRev   int64     `json:"rpcHimarkRev"`
	RpcSnd         float32   `json:"rpcSnd"`
	RpcRcv         float32   `json:"rpcRcv"`
	Tables         map[string]*Table
	duplicateKey   bool
	completed      bool
	hasTrackInfo   bool
	running        int
}

// Table stores track information per table (part of Command)
type Table struct {
	TableName      string
	PagesIn        int
	PagesOut       int
	PagesCached    int
	ReadLocks      int
	WriteLocks     int
	GetRows        int
	PosRows        int
	ScanRows       int
	PutRows        int
	DelRows        int
	TotalReadWait  int
	TotalReadHeld  int
	TotalWriteWait int
	TotalWriteHeld int
	MaxReadWait    int
	MaxReadHeld    int
	MaxWriteWait   int
	MaxWriteHeld   int
	PeekCount      int
	TotalPeekWait  int
	TotalPeekHeld  int
	MaxPeekWait    int
	MaxPeekHeld    int
	TriggerLapse   float32
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
	c.RpcMsgsIn, _ = strconv.ParseInt(string(rpcMsgsIn), 10, 64)
	c.RpcMsgsOut, _ = strconv.ParseInt(string(rpcMsgsOut), 10, 64)
	c.RpcSizeIn, _ = strconv.ParseInt(string(rpcSizeIn), 10, 64)
	c.RpcSizeOut, _ = strconv.ParseInt(string(rpcSizeOut), 10, 64)
	c.RpcHimarkFwd, _ = strconv.ParseInt(string(rpcHimarkFwd), 10, 64)
	c.RpcHimarkRev, _ = strconv.ParseInt(string(rpcHimarkRev), 10, 64)
	if rpcSnd != nil {
		f, _ := strconv.ParseFloat(string(rpcSnd), 32)
		c.RpcSnd = float32(f)
	}
	if rpcRcv != nil {
		f, _ := strconv.ParseFloat(string(rpcRcv), 32)
		c.RpcRcv = float32(f)
	}
}

// MarshalJSON - handle time formatting
func (c *Command) MarshalJSON() ([]byte, error) {
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
		UCpu           int64   `json:"uCpu"`
		SCpu           int64   `json:"sCpu"`
		DiskIn         int64   `json:"diskIn"`
		DiskOut        int64   `json:"diskOut"`
		IpcIn          int64   `json:"ipcIn"`
		IpcOut         int64   `json:"ipcOut"`
		MaxRss         int64   `json:"maxRss"`
		PageFaults     int64   `json:"pageFaults"`
		RpcMsgsIn      int64   `json:"rpcMsgsIn"`
		RpcMsgsOut     int64   `json:"rpcMsgsOut"`
		RpcSizeIn      int64   `json:"rpcSizeIn"`
		RpcSizeOut     int64   `json:"rpcSizeOut"`
		RpcHimarkFwd   int64   `json:"rpcHimarkFwd"`
		RpcHimarkRev   int64   `json:"rpcHimarkRev"`
		RpcSnd         float32 `json:"rpcSnd"`
		RpcRcv         float32 `json:"rpcRcv"`
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
		UCpu:           c.UCpu,
		SCpu:           c.SCpu,
		DiskIn:         c.DiskIn,
		DiskOut:        c.DiskOut,
		IpcIn:          c.IpcIn,
		IpcOut:         c.IpcOut,
		MaxRss:         c.MaxRss,
		PageFaults:     c.PageFaults,
		RpcMsgsIn:      c.RpcMsgsIn,
		RpcMsgsOut:     c.RpcMsgsOut,
		RpcSizeIn:      c.RpcSizeIn,
		RpcSizeOut:     c.RpcSizeOut,
		RpcHimarkFwd:   c.RpcHimarkFwd,
		RpcHimarkRev:   c.RpcHimarkRev,
		RpcSnd:         c.RpcSnd,
		RpcRcv:         c.RpcRcv,
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
	if other.RpcMsgsIn > 0 {
		c.RpcMsgsIn = other.RpcMsgsIn
	}
	if other.RpcMsgsOut > 0 {
		c.RpcMsgsOut = other.RpcMsgsOut
	}
	if other.RpcMsgsIn > 0 {
		c.RpcMsgsIn = other.RpcMsgsIn
	}
	if other.RpcSizeIn > 0 {
		c.RpcSizeIn = other.RpcSizeIn
	}
	if other.RpcSizeOut > 0 {
		c.RpcSizeOut = other.RpcSizeOut
	}
	if other.RpcHimarkFwd > 0 {
		c.RpcHimarkFwd = other.RpcHimarkFwd
	}
	if other.RpcHimarkRev > 0 {
		c.RpcHimarkRev = other.RpcHimarkRev
	}
	if other.RpcSnd > 0 {
		c.RpcSnd = other.RpcSnd
	}
	if other.RpcRcv > 0 {
		c.RpcRcv = other.RpcRcv
	}
}

// P4dFileParser - manages state
type P4dFileParser struct {
	lineNo               int64
	cmds                 map[int64]*Command
	inchan               chan []byte
	outchan              chan string
	currStartTime        time.Time
	timeLastCmdProcessed time.Time
	pidsSeenThisSecond   map[int64]bool
	running              int
	block                *Block
}

// NewP4dFileParser - create and initialise properly
func NewP4dFileParser() *P4dFileParser {
	var fp P4dFileParser
	fp.cmds = make(map[int64]*Command)
	fp.pidsSeenThisSecond = make(map[int64]bool)
	fp.block = new(Block)
	return &fp
}

func (fp *P4dFileParser) addCommand(newCmd *Command, hasTrackInfo bool) {
	newCmd.running = fp.running
	if fp.currStartTime != newCmd.StartTime && newCmd.StartTime.After(fp.currStartTime) {
		fp.currStartTime = newCmd.StartTime
		fp.pidsSeenThisSecond = make(map[int64]bool)
	}
	if cmd, ok := fp.cmds[newCmd.Pid]; ok {
		if cmd.ProcessKey != newCmd.ProcessKey {
			fp.outputCmd(cmd)
			fp.cmds[newCmd.Pid] = newCmd // Replace previous cmd with same PID
		} else if bytes.Equal(newCmd.Cmd, []byte("rmt-FileFetch")) ||
			bytes.Equal(newCmd.Cmd, []byte("rmt-Journal")) ||
			bytes.Equal(newCmd.Cmd, []byte("pull")) {
			if hasTrackInfo {
				cmd.updateFrom(newCmd)
			} else {
				fp.outputCmd(cmd)
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
var reTrackRPC = regexp.MustCompile(`^--- rpc msgs/size in\+out (\d+)\+(\d+)/(\d+)mb\+(\d+)mb himarks (\d+)/(\d+)`)
var reTrackRPC2 = regexp.MustCompile(`^--- rpc msgs/size in\+out (\d+)\+(\d+)/(\d+)mb\+(\d+)mb himarks (\d+)/(\d+) snd/rcv ([0-9]+|[0-9]+\.[0-9]+|\.[0-9]+)s/([0-9]+|[0-9]+\.[0-9]+|\.[0-9]+)s`)
var reTrackUsage = regexp.MustCompile(`^--- usage (\d+)\+(\d+)us (\d+)\+(\d+)io (\d+)\+(\d+)net (\d+)k (\d+)pf`)

func (fp *P4dFileParser) processTrackRecords(cmd *Command, lines [][]byte) {
	hasTrackInfo := false
	for _, line := range lines {
		if bytes.Equal(trackLapse, line[:len(trackLapse)]) {
			val := line[len(trackLapse):]
			i := bytes.IndexByte(val, '.')
			j := bytes.IndexByte(val, 's')
			if i >= 0 && j > 0 {
				f, _ := strconv.ParseFloat(string(val[i:j-i]), 32)
				cmd.CompletedLapse = float32(f)
			}
		} else if bytes.Equal(trackDB, line[:len(trackDB)]) {
			tableName := string(line[len(trackDB):])
			t := newTable(tableName)
			cmd.Tables[tableName] = t
			hasTrackInfo = true
		} else if bytes.Equal(trackMeta, line[:len(trackMeta)]) ||
			bytes.Equal(trackChange, line[:len(trackChange)]) ||
			bytes.Equal(trackClients, line[:len(trackClients)]) {
			// Special tables don't have trackInfo set
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
	}
	cmd.hasTrackInfo = hasTrackInfo
	fp.addCommand(cmd, hasTrackInfo)
}

// Output a single command to appropriate channel
func (fp *P4dFileParser) outputCmd(cmd *Command) {
	lines := []string{}
	lines = append(lines, fmt.Sprintf("%v", cmd))
	if len(lines) > 0 && len(lines[0]) > 0 {
		fp.outchan <- strings.Join(lines, `\n`)
	}
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
			fp.outputCmd(cmd)
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
		fp.outputCmd(cmd)
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
			//TODO - proper trigger support - for now just remove
			if i := bytes.Index(line, []byte("' trigger ")); i >= 0 {
				line = line[:i+1]
			}
			h := md5.Sum(line)
			cmd.ProcessKey = hex.EncodeToString(h[:])
			fp.addCommand(cmd, false)
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
	close(fp.outchan)
}

// LogParser - interface to be run on a go routine
func (fp *P4dFileParser) LogParser(inchan chan []byte, outchan chan string) {
	fp.inchan = inchan
	fp.outchan = outchan
	// timer := time.NewTimer(time.Second * 1)
	fp.lineNo = 1
	for {
		select {
		case <-time.After(time.Second * 1):
			fp.outputCompletedCommands()
		case line, ok := <-fp.inchan:
			if ok {
				line = bytes.TrimRight(line, "\r\n")
				fp.parseLine(line)
			} else {
				fp.parseFinish()
				return
			}
		}
	}
}

// P4LogParseFile - interface for parsing a specified file
func (fp *P4dFileParser) P4LogParseFile(opts P4dParseOptions, outchan chan string) {
	fp.outchan = outchan
	var scanner *bufio.Scanner
	if len(opts.testInput) > 0 {
		scanner = bufio.NewScanner(strings.NewReader(opts.testInput))
	} else if opts.File == "-" {
		scanner = bufio.NewScanner(os.Stdin)
	} else {
		file, err := os.Open(opts.File)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		const maxCapacity = 1024 * 1024
		buf := make([]byte, maxCapacity)
		reader := bufio.NewReaderSize(file, maxCapacity)
		scanner = bufio.NewScanner(reader)
		scanner.Buffer(buf, maxCapacity)
	}
	fp.lineNo = 1
	for scanner.Scan() {
		line := scanner.Bytes()
		fp.parseLine(line)
	}
	fp.parseFinish()
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "reading file %s:%s\n", opts.File, err)
	}

}
