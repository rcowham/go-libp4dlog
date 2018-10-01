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

var reCmd = regexp.MustCompile(`^\t(\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d) pid (\d+) ([^ @]*)@([^ ]*) ([^ ]*) \[([^\]]*)\] \'([\w-]+) (.*)\'.*`)
var reCmdNoarg = regexp.MustCompile(`^\t(\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d) pid (\d+) ([^ @]*)@([^ ]*) ([^ ]*) \[([^\]]*)\] \'([\w-]+)\'.*`)
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
	block.lines = append(block.lines, line)
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
	duplicateKey   bool
	completed      bool
	hasTrackInfo   bool
	running        int
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
	}{
		ProcessKey:     c.ProcessKey,
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
	// Others to consider
	// "uCpu",
	// "sCpu", "diskIn", "diskOut", "ipcIn", "ipcOut", "maxRss",
	// "pageFaults", "rpcMsgsIn", "rpcMsgsOut", "rpcSizeOut",
	// "rpcSizeIn", "rpcHimarkFwd", "rpcHimarkRev", "error",
	// "rpcSnd", "rpcRcv"]:
}

// P4dFileParser - manages state
type P4dFileParser struct {
	lineNo             int64
	cmds               map[int64]*Command
	inchan             chan []byte
	outchan            chan string
	currStartTime      time.Time
	pidsSeenThisSecond map[int64]bool
	running            int
	block              *Block
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

// From Python version:
// self.tables = {}
// # Use line number from original cmd if appropriate
// if cmd.pid in self.cmds and cmd.processKey == self.cmds[cmd.pid].processKey:
// 	cmd.lineNumber = self.cmds[cmd.pid].lineNumber
// tablesTracked = []
// trackProcessor = TrackProcessor(self.logger)
// trackProcessor.processTrackLines(cmd, lines, self.tables, tablesTracked)
// if cmd.completedLapse is not None:
// 	cmd.setEndTime(dateAdd(cmd.startTime, float(cmd.completedLapse)))
// else:
// 	cmd.setEndTime(cmd.startTime)
// # Don't set tracked info if is one of the special commands which can occur multiple times and
// # which don't indicate the completion of the command
// hasTrackInfo = False
// for t in tablesTracked:
// 	if not t.startswith("meta_") and not t.startswith("changes_") and not t.startswith("clients_"):
// 		hasTrackInfo = True
// self.addCommand(cmd, hasTrackInfo=hasTrackInfo)
// if hasTrackInfo:
// 	self.cmd_tables_insert(cmd, self.tables)
// else:
// 	# Save special tables for processing when cmd is completed
// 	for t in self.tables.keys():
// 		self.cmds[cmd.pid].tables[t] = self.tables[t]

func (fp *P4dFileParser) processTrackRecords(cmd *Command, lines [][]byte) {
	// Currently a null op - we can ignore tracked records
	cmd.hasTrackInfo = true
	for _, line := range lines {
		if bytes.Equal(trackLapse, line[:len(trackLapse)]) {
			val := line[len(trackLapse):]
			i := bytes.IndexByte(val, '.')
			j := bytes.IndexByte(val, 's')
			if i >= 0 && j > 0 {
				f, _ := strconv.ParseFloat(string(val[i:j-i]), 32)
				cmd.CompletedLapse = float32(f)
			}
		}
	}
	fp.addCommand(cmd, true)
}

// Output a single command to appropriate channel
func (fp *P4dFileParser) outputCmd(cmd *Command) {
	if fp.outchan != nil {
		lines := []string{}
		lines = append(lines, fmt.Sprintf("%v", cmd))
		if len(lines) > 0 && len(lines[0]) > 0 {
			fp.outchan <- strings.Join(lines, `\n`)
		}
	}
}

// Output all completed commands 3 or more seconds ago
func (fp *P4dFileParser) outputCompletedCommands() {
	for _, cmd := range fp.cmds {
		completed := false
		if cmd.completed && (cmd.hasTrackInfo || fp.currStartTime.Sub(cmd.EndTime) >= 3*time.Second) {
			completed = true
		}
		if !completed && (cmd.hasTrackInfo && cmd.EndTime != blankTime &&
			fp.currStartTime.Sub(cmd.EndTime) >= 3*time.Second) {
			completed = true
		}
		if completed {
			fp.outputCmd(cmd)
			delete(fp.cmds, cmd.Pid)
			fp.running--
		}
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
	}
}

func (fp *P4dFileParser) processInfoBlock(block *Block) {

	var cmd *Command
	i := 0
	for _, line := range block.lines[1:] {
		i++
		if cmd != nil && bytes.Equal(trackStart, line[:3]) {
			fp.processTrackRecords(cmd, block.lines[i:])
			break // Block has been processed
		}

		m := reCmd.FindSubmatch(line)
		if len(m) == 0 {
			m = reCmdNoarg.FindSubmatch(line)
		}
		if len(m) > 0 {
			cmd = new(Command)
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
	timer := time.NewTimer(time.Second * 1)
	for {
		select {
		case <-timer.C:
			fp.outputCompletedCommands()
		case line, ok := <-fp.inchan:
			if ok {
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
		reader := bufio.NewReaderSize(file, 1024*1024) // Read in chunks
		scanner = bufio.NewScanner(reader)
	}
	fp.lineNo = 0
	for scanner.Scan() {
		line := scanner.Bytes()
		fp.parseLine(line)
	}
	fp.parseFinish()
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "reading file %s:%s\n", opts.File, err)
	}

}
