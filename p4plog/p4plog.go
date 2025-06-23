/*
Package p4plog parses p4p Perforce P4 Proxy text logs.

It assumes you have set configurable track=1for p4p logging.

See p4plog_test.go for examples of log entries.
*/
package p4plog

import (
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// GO standard reference value/format: Mon Jan 2 15:04:05 -0700 MST 2006
const p4timeformat = "2006/01/02 15:04:05"

// DebugLevel - for different levels of debugging
type DebugLevel int

const (
	DebugBasic DebugLevel = 1 << iota
	DebugCommands
)

// FlagSet - true if specified level set
func FlagSet(flag int, level DebugLevel) bool {
	return flag&int(level) > 0
}

var infoBlock = "Perforce proxy info:"

func toInt64(buf string) (n int64) {
	for _, v := range buf {
		n = n*10 + int64(v-'0')
	}
	return
}

type blockType int

const (
	blankType blockType = iota
	infoType
	errorType
	activeThreadsType
	pausedThreadsType
	resourcePressureType
)

// Block is a block of lines parsed from a file
type Block struct {
	lineNo int64
	btype  blockType
	lines  []string
}

func (block *Block) addLine(line string, lineNo int64) {
	// if first line we detect block type and avoid copy
	if block.lineNo == 0 {
		block.lineNo = lineNo
	}
	if len(block.lines) == 0 && block.btype == blankType {
		if len(line) == 0 {
			block.btype = blankType
		} else if strings.HasPrefix(line, infoBlock) {
			block.btype = infoType
		} else {
			block.btype = errorType
		}
		return
	}
	block.lines = append(block.lines, line)
}

// ProxyCommand is a command found in the block
type ProxyCommand struct {
	Pid                   int64     `json:"pid"`
	LineNo                int64     `json:"lineNo"`
	EndTime               time.Time `json:"endTime"`
	CompletedLapse        float32   `json:"completedLapse"`
	IP                    string    `json:"ip"`
	ProxyTotalsSvr        int64     `json:"proxyTotalsSvr"`
	ProxyTotalsCache      int64     `json:"proxyTotalsCache"`
	ProxyTotalsSvrBytes   int64     `json:"proxyTotalsSvrBytes"`
	ProxyTotalsCacheBytes int64     `json:"proxyTotalsCacheBytes"`
}

func newCommand() *ProxyCommand {
	c := new(ProxyCommand)
	return c
}

func (c *ProxyCommand) String() string {
	j, _ := json.Marshal(c)
	return string(j)
}

func (c *ProxyCommand) setEndTime(t string) {
	c.EndTime, _ = time.Parse(p4timeformat, t)
}

// var reTrackProxyTotals = regexp.MustCompile(`^--- proxytotals files/size svr\+cache (\d+)\+(\d+)/(\d+)(\S)\+(\d+)(\S)`)
func (c *ProxyCommand) setProxyTotals(proxyTotalsSvr, proxyTotalsCache, proxyTotalsSvrBytes, proxyTotalsCacheBytes string) {
	c.ProxyTotalsSvr, _ = strconv.ParseInt(proxyTotalsSvr, 10, 64)
	c.ProxyTotalsSvrBytes = parseBytesString(proxyTotalsSvrBytes)
	c.ProxyTotalsCache, _ = strconv.ParseInt(proxyTotalsCache, 10, 64)
	c.ProxyTotalsCacheBytes = parseBytesString(proxyTotalsCacheBytes)
}

// func (c *ProxyCommand) setUsage(uCPU, sCPU, diskIn, diskOut, ipcIn, ipcOut, maxRss, pageFaults string) {
// 	c.UCpu, _ = strconv.ParseInt(uCPU, 10, 64)
// 	c.SCpu, _ = strconv.ParseInt(sCPU, 10, 64)
// 	c.DiskIn, _ = strconv.ParseInt(diskIn, 10, 64)
// 	c.DiskOut, _ = strconv.ParseInt(diskOut, 10, 64)
// 	c.IpcIn, _ = strconv.ParseInt(ipcIn, 10, 64)
// 	c.IpcOut, _ = strconv.ParseInt(ipcOut, 10, 64)
// 	c.MaxRss, _ = strconv.ParseInt(maxRss, 10, 64)
// 	c.PageFaults, _ = strconv.ParseInt(pageFaults, 10, 64)
// }

// MarshalJSON - handle time formatting
func (c *ProxyCommand) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Pid                   int64   `json:"pid"`
		LineNo                int64   `json:"lineNo"`
		CompletedLapse        float32 `json:"completedLapse"`
		EndTime               string  `json:"endTime"`
		ProxyTotalsSvr        int64   `json:"proxyTotalsSvr"`        // Valid for syncs
		ProxyTotalsCache      int64   `json:"proxyTotalsCache"`      // Valid for syncs
		ProxyTotalsSvrBytes   int64   `json:"proxyTotalsSvrBytes"`   // Valid for syncs
		ProxyTotalsCacheBytes int64   `json:"proxyTotalsCacheBytes"` // Valid for syncs
	}{
		Pid:                   c.Pid,
		LineNo:                c.LineNo,
		CompletedLapse:        c.CompletedLapse,
		EndTime:               c.EndTime.Format(p4timeformat),
		ProxyTotalsSvr:        c.ProxyTotalsSvr,
		ProxyTotalsCache:      c.ProxyTotalsCache,
		ProxyTotalsSvrBytes:   c.ProxyTotalsSvrBytes,
		ProxyTotalsCacheBytes: c.ProxyTotalsCacheBytes,
	})
}

var blankTime time.Time

// P4pFileParser - manages state
type P4pFileParser struct {
	logger    *logrus.Logger
	lineNo    int64
	m         sync.Mutex
	CmdsCount int //Count of commands processed
	cmdChan   chan interface{}
	linesChan *<-chan string
	blockChan chan *Block
	debug     int
}

// NewP4pFileParser - create and initialise properly
func NewP4pFileParser(logger *logrus.Logger) *P4pFileParser {
	var fp P4pFileParser
	fp.logger = logger
	return &fp
}

// SetDebugMode - turn on debugging - very verbose!
func (fp *P4pFileParser) SetDebugMode(level int) {
	fp.debug = level
}

const trackStart = "---"
const trackLapse = "--- lapse "

// const prefixTrackRPC = "--- rpc msgs/size in+out "
const prefixTrackProxyTotals = "--- proxytotals files/size svr+cache "

// var reTrackRPC = regexp.MustCompile(`^--- rpc msgs/size in\+out (\d+)\+(\d+)/(\d+)mb\+(\d+)mb himarks (\d+)/(\d+)`)
// var reTrackRPC2 = regexp.MustCompile(`^--- rpc msgs/size in\+out (\d+)\+(\d+)/(\d+)mb\+(\d+)mb himarks (\d+)/(\d+) snd/rcv ([0-9]+|[0-9]+\.[0-9]+|\.[0-9]+)s/([0-9]+|[0-9]+\.[0-9]+|\.[0-9]+)s`)
var reTrackProxyTotals = regexp.MustCompile(`^--- proxytotals files/size svr\+cache (\d+)\+(\d+)/([0-9.]+[BKMGTP])\+([0-9.]+[BKMGTP])`)

// --- proxytotals files/size svr+cache 1403+203/25.6M+254M

// const prefixTrackUsage = "--- usage"

// var reTrackUsage = regexp.MustCompile(`^--- usage (\d+)\+(\d+)us (\d+)\+(\d+)io (\d+)\+(\d+)net (\d+)k (\d+)pf`)
// var reCmdUsage = regexp.MustCompile(` (\d+)\+(\d+)us (\d+)\+(\d+)io (\d+)\+(\d+)net (\d+)k (\d+)pf`)
var reCompleted = regexp.MustCompile(`^\t(\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d) pid (\d+) completed ([0-9]+|[0-9]+\.[0-9]+|\.[0-9]+)s.*`)

func (fp *P4pFileParser) processTrackRecords(cmd *ProxyCommand, lines []string) {
	for _, line := range lines {
		if strings.HasPrefix(line, trackLapse) {
			val := line[len(trackLapse):]
			j := strings.Index(val, "s")
			if j > 0 {
				f, _ := strconv.ParseFloat(string(val[:j]), 32)
				cmd.CompletedLapse = float32(f)
			}
			continue
		}

		if !strings.HasPrefix(line, trackStart) {
			continue
		}
		var m []string
		// if strings.HasPrefix(line, prefixTrackUsage) {
		// 	m = reTrackUsage.FindStringSubmatch(line)
		// 	if len(m) > 0 {
		// 		cmd.setUsage(m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8])
		// 		continue
		// 	}
		// }
		// if strings.HasPrefix(line, prefixTrackRPC) {
		// 	m = reTrackRPC2.FindStringSubmatch(line)
		// 	if len(m) > 0 {
		// 		cmd.setRPC(m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8])
		// 		continue
		// 	}
		// 	m = reTrackRPC.FindStringSubmatch(line)
		// 	if len(m) > 0 {
		// 		cmd.setRPC(m[1], m[2], m[3], m[4], m[5], m[6], "", "")
		// 		continue
		// 	}
		// }
		//var reTrackProxyTotals = regexp.MustCompile(`^--- proxytotals files/size svr\+cache (\d+)\+(\d+)/(\d+)(\S)\+(\d+)(\S)`)
		if strings.HasPrefix(line, prefixTrackProxyTotals) {
			m = reTrackProxyTotals.FindStringSubmatch(line)
			if len(m) > 0 {
				cmd.setProxyTotals(m[1], m[2], m[3], m[4])
				continue
			}
		}
	}
	fp.outputCmd(cmd)
}

// Extract values from strings such as "1.1K" or "2.3G"
func parseBytesString(value string) int64 {
	l := value[len(value)-1:]
	s, _ := strconv.ParseFloat(value[:len(value)-1], 32)
	var rtnVal int64
	switch l {
	case "B":
		rtnVal = int64(s)
	case "K":
		rtnVal = int64(s * 1024)
	case "M":
		rtnVal = int64(s * 1024 * 1024)
	case "G":
		rtnVal = int64(s * 1024 * 1024 * 1024)
	case "T":
		rtnVal = int64(s * 1024 * 1024 * 1024 * 1024)
	case "P":
		rtnVal = int64(s * 1024 * 1024 * 1024 * 1024 * 1024)
	default:
		f, _ := strconv.ParseFloat(value, 32)
		rtnVal = int64(f)
	}
	return rtnVal
}

// Output a single command to appropriate channel
func (fp *P4pFileParser) outputCmd(cmd *ProxyCommand) {
	// Ensure entire structure is copied, particularly map member to avoid concurrency issues
	cmdcopy := *cmd
	fp.cmdChan <- cmdcopy
	fp.CmdsCount++
}

func (fp *P4pFileParser) updateCompletionTime(cmd *ProxyCommand, pid int64, endTime string, completedLapse string) {
	cmd.setEndTime(endTime)
	f, _ := strconv.ParseFloat(string(completedLapse), 32)
	cmd.CompletedLapse = float32(f)
}

func (fp *P4pFileParser) processInfoBlock(block *Block) {

	var cmd *ProxyCommand
	ind := 0
	for _, line := range block.lines {
		if cmd != nil && strings.HasPrefix(line, trackStart) {
			fp.processTrackRecords(cmd, block.lines[ind:])
			return // Block has been processed
		}
		ind++

		// process completed
		var pid int64
		m := reCompleted.FindStringSubmatch(line)
		if len(m) > 0 {
			pid = toInt64(m[2])
			cmd = newCommand()
			cmd.LineNo = block.lineNo
			cmd.Pid = toInt64(m[2])
			fp.updateCompletionTime(cmd, pid, m[1], m[3])
		}
	}
}

func (fp *P4pFileParser) processErrorBlock(block *Block) {
	// var cmd *ProxyCommand
	// for _, line := range block.lines {
	// 	m := rePid.FindStringSubmatch(line)
	// 	if len(m) > 0 {
	// 		pid := toInt64(m[1])
	// 		ok := false
	// 		if cmd, ok = fp.cmds[pid]; ok {
	// 			cmd.CmdError = true
	// 		}
	// 		return
	// 	}
	// }
}

func (fp *P4pFileParser) processBlock(block *Block) {
	if block.btype == infoType {
		fp.processInfoBlock(block)
	} else if block.btype == errorType {
		fp.processErrorBlock(block)
	} //TODO: output unrecognised block if wanted
}

func blankLine(line string) bool {
	return len(line) == 0
}

// Basic strings which start/end a block
var blockEnds = []string{
	"Perforce proxy info:",
	"Perforce proxy error:",
}

// Various line prefixes that both can end a block, and should be ignored - see ignoreLine
var BlockEndPrefixes = []string{}

func blockEnd(line string) bool {
	if blankLine(line) {
		return true
	}
	for _, str := range blockEnds {
		if line == str {
			return true
		}
	}
	for _, str := range BlockEndPrefixes {
		if strings.HasPrefix(line, str) {
			return true
		}
	}
	return false
}

// Lines to be ignored and not added to blocks
func ignoreLine(line string) bool {
	for _, str := range BlockEndPrefixes {
		if strings.HasPrefix(line, str) {
			return true
		}
	}
	return false
}

// LogParser - interface to be run on a go routine - commands are returned on cmdchan
func (fp *P4pFileParser) LogParser(ctx context.Context, linesChan <-chan string) chan interface{} {
	fp.lineNo = 1

	fp.cmdChan = make(chan interface{}, 10000)
	fp.linesChan = &linesChan
	fp.blockChan = make(chan *Block, 1000)

	// Go routine to process all the lines being received
	// sends blocks on the blockChannel
	go func() {
		defer close(fp.blockChan)
		block := new(Block)
		for {
			select {
			case <-ctx.Done():
				if fp.logger != nil {
					fp.logger.Debugf("lines got Done")
				}
				return
			case line, ok := <-linesChan:
				if ok {
					line = strings.TrimRight(line, "\r\n")
					if blockEnd(line) {
						if len(block.lines) > 0 {
							if !blankLine(block.lines[0]) {
								fp.blockChan <- block
							}
						}
						block = new(Block)
						if !ignoreLine(line) {
							block.addLine(line, fp.lineNo)
						}
					} else {
						if !ignoreLine(line) {
							block.addLine(line, fp.lineNo)
						}
					}
					fp.lineNo++
				} else {
					if fp.logger != nil {
						fp.logger.Debugf("LogParser lines channel closed")
					}
					if len(block.lines) > 0 && !blankLine(block.lines[0]) {
						fp.blockChan <- block
					}
					return
				}
			}
		}
	}()

	// This routine handles blocks in parallel to lines above
	go func() {
		defer close(fp.cmdChan)
		for {
			select {
			case <-ctx.Done():
				if fp.logger != nil {
					fp.logger.Debugf("lines got Done")
				}
				return
			case b, ok := <-fp.blockChan:
				if ok {
					fp.processBlock(b)
				} else {
					return
				}
			}
		}
	}()

	return fp.cmdChan
}
