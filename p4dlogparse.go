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

	jsoniter "github.com/json-iterator/go"
)

// Ref format: Mon Jan 2 15:04:05 -0700 MST 2006
const p4timeformat = "2006/01/02 15:04:05"

var reCmd = regexp.MustCompile(`^\t(\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d) pid (\d+) ([^ @]*)@([^ ]*) ([^ ]*) \[([^\]]*)\] \'([\w-]+) (.*)\'.*`)
var reCmdNoarg = regexp.MustCompile(`^\t(\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d) pid (\d+) ([^ @]*)@([^ ]*) ([^ ]*) \[([^\]]*)\] \'([\w-]+)\'.*`)
var reCompute = regexp.MustCompile(`^\t(\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d) pid (\d+) compute end ([0-9]+|[0-9]+\.[0-9]+|\.[0-9]+)s.*`)
var reCompleted = regexp.MustCompile(`^\t(\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d) pid (\d+) completed ([0-9]+|[0-9]+\.[0-9]+|\.[0-9]+)s.*`)
var reJSONCmdargs = regexp.MustCompile(`^(.*) \{.*\}$`)

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
	ComputeLapse   []byte    `json:"computeLapse"`
	CompletedLapse []byte    `json:"completedLapse"`
	IP             []byte    `json:"ip"`
	App            []byte    `json:"app"`
	Args           []byte    `json:"args"`
	duplicateKey   bool
	completed      bool
	hasTrackInfo   bool
	running        int
}

func (c *Command) String() string {
	var json = jsoniter.ConfigCompatibleWithStandardLibrary
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
		ProcessKey     string `json:"processKey"`
		Cmd            string `json:"cmd"`
		Pid            int64  `json:"pid"`
		LineNo         int64  `json:"lineNo"`
		User           string `json:"user"`
		Workspace      string `json:"workspace"`
		ComputeLapse   string `json:"computeLapse"`
		CompletedLapse string `json:"completedLapse"`
		IP             string `json:"ip"`
		App            string `json:"app"`
		Args           string `json:"args"`
		StartTime      string `json:"startTime"`
		EndTime        string `json:"endTime"`
	}{
		ProcessKey:     c.ProcessKey,
		Cmd:            string(c.Cmd),
		Pid:            c.Pid,
		LineNo:         c.LineNo,
		User:           string(c.User),
		Workspace:      string(c.Workspace),
		ComputeLapse:   string(c.ComputeLapse),
		CompletedLapse: string(c.CompletedLapse),
		IP:             string(c.IP),
		App:            string(c.App),
		Args:           string(c.Args),
		StartTime:      c.StartTime.Format(p4timeformat),
		EndTime:        c.EndTime.Format(p4timeformat),
	})
}

func (c *Command) updateFrom(cmd *Command) {
	// Do Nothing
}

// P4dOutputCallback is function to output JSON objects
type P4dOutputCallback func(output string)

// P4dFileParser manages state
type P4dFileParser struct {
	lineNo             int64
	cmds               map[int64]*Command
	output             P4dOutputCallback
	currStartTime      time.Time
	pidsSeenThisSecond map[int64]bool
	running            int
}

// NewP4dFileParser - create and initialise properly
func NewP4dFileParser(callback P4dOutputCallback) *P4dFileParser {
	var fp P4dFileParser
	fp.cmds = make(map[int64]*Command)
	fp.pidsSeenThisSecond = make(map[int64]bool)
	fp.output = callback
	return &fp
}

func (fp *P4dFileParser) addCommand(newCmd *Command, hasTrackInfo bool) {
	newCmd.running = fp.running
	if fp.currStartTime != newCmd.StartTime && newCmd.StartTime.After(fp.currStartTime) {
		fp.currStartTime = newCmd.StartTime
		fp.pidsSeenThisSecond = make(map[int64]bool)
	}
	if cmd, ok := fp.cmds[newCmd.Pid]; ok {
		if cmd.ProcessKey == newCmd.ProcessKey {
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
		fp.outputCompletedCommands()
	}
}

// Output a single command to callback
func (fp *P4dFileParser) outputCmd(cmd *Command) {
	if fp.output != nil {
		lines := []string{}
		lines = append(lines, fmt.Sprintf("%v", cmd))
		if len(lines) > 0 && len(lines[0]) > 0 {
			fp.output(strings.Join(lines, `\n`))
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
		if !completed && (cmd.hasTrackInfo && fp.currStartTime.Sub(cmd.EndTime) >= 3*time.Second) {
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
	sum := 0.0
	if cmd, ok := fp.cmds[pid]; ok {
		// sum all compute values for same command
		sum, _ = strconv.ParseFloat(string(cmd.ComputeLapse), 32)
		f, _ := strconv.ParseFloat(string(computeLapse), 32)
		cmd.ComputeLapse = []byte(strconv.FormatFloat(sum+f, 'f', -1, 32))
	}

}

func (fp *P4dFileParser) updateCompletionTime(pid int64, endTime []byte, completedLapse []byte) {
	if cmd, ok := fp.cmds[pid]; ok {
		cmd.CompletedLapse = endTime
		cmd.setEndTime(endTime)
		f, _ := strconv.ParseFloat(string(completedLapse), 32)
		cmd.CompletedLapse = []byte(strconv.FormatFloat(f, 'f', -1, 32))
	}
}

func (fp *P4dFileParser) processInfoBlock(block *Block) {

	var cmd *Command
	i := 0
	for _, line := range block.lines[1:] {
		i++
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

// P4LogParseFile - interface for parsing a specified file
func (fp *P4dFileParser) P4LogParseFile(opts P4dParseOptions) {
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
	infoBlock := []byte("Perforce server info:")
	block := new(Block)
	for scanner.Scan() {
		line := scanner.Bytes()
		if blockEnd(line) {
			if len(block.lines) > 0 {
				if bytes.Equal(block.lines[0], infoBlock) {
					fp.processInfoBlock(block)
				} else if blankLine(block.lines[0]) {
					fp.outputCompletedCommands()
				}
			}
			block = new(Block)
			block.addLine(line, fp.lineNo)
		} else {
			block.addLine(line, fp.lineNo)
		}
		fp.lineNo++
	}
	if len(block.lines) > 0 {
		if bytes.Equal(block.lines[0], infoBlock) {
			fp.processInfoBlock(block)
		}
	}
	fp.outputRemainingCommands()
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "reading file %s:%s\n", opts.File, err)
	}

}
