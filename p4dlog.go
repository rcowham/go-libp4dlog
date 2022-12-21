/*
Package p4dlog parses Perforce Hexlix Core Server text logs (not structured logs).

These are logs created by p4d, as documented by:

https://community.perforce.com/s/article/2525

It assumes you have set configurable server=3 (or greater)
You may also have decided to set track=1 to get more detailed usage of
access to different tables.

See p4dlog_test.go for examples of log entries.
*/
package p4dlog

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// GO standard reference value/format: Mon Jan 2 15:04:05 -0700 MST 2006
const p4timeformat = "2006/01/02 15:04:05"

// This defines the maximum number of running commands we allow
// Exceeding this values means either a bug in the parser or something
// simple like server=1 logging only set (so no completion records)
// In future we may allow this to be set by parameter if required.
const maxRunningCount = 20000

// DebugLevel - for different levels of debugging
type DebugLevel int

const (
	DebugBasic DebugLevel = 1 << iota
	DebugDatabase
	DebugJSON
	DebugCommands
	DebugTrackRunning
	DebugUnrecognised
	DebugPending
	DebugPendingCounts
	DebugMetricStats
)

// FlagSet - true if specified level set
func FlagSet(flag int, level DebugLevel) bool {
	return flag&int(level) > 0
}

var reCmd = regexp.MustCompile(`^\t(\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d) pid (\d+) ([^ @]*)@([^ ]*) ([^ ]*) \[(.*?)\] \'([\w-]+) (.*)\'.*`)
var reCmdNoarg = regexp.MustCompile(`^\t(\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d) pid (\d+) ([^ @]*)@([^ ]*) ([^ ]*) \[(.*?)\] \'([\w-]+)\'.*`)
var reCmdMultiLineDesc = regexp.MustCompile(`^\t(\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d) pid (\d+) ([^ @]*)@([^ ]*) ([^ ]*) \[(.*?)\] \'([\w-]+)([^\']*)`)
var reCompute = regexp.MustCompile(`^\t(\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d) pid (\d+) compute end ([0-9]+|[0-9]+\.[0-9]+|\.[0-9]+)s.*`)
var reCompleted = regexp.MustCompile(`^\t(\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d) pid (\d+) completed ([0-9]+|[0-9]+\.[0-9]+|\.[0-9]+)s.*`)
var reJSONCmdargs = regexp.MustCompile(`^(.*) \{.*\}$`)

var infoBlock = "Perforce server info:"
var errorBlock = "Perforce server error:"

func toInt64(buf string) (n int64) {
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

type blockType int

const (
	blankType blockType = iota
	infoType
	errorType
	activeThreadsType
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
		} else if strings.HasSuffix(line, msgActiveThreads) {
			block.btype = activeThreadsType
			block.lines = append(block.lines, line)
		} else {
			block.btype = errorType
		}
		return
	}
	block.lines = append(block.lines, line)
}

// Command is a command found in the block
type Command struct {
	ProcessKey       string    `json:"processKey"`
	Cmd              string    `json:"cmd"`
	Pid              int64     `json:"pid"`
	LineNo           int64     `json:"lineNo"`
	User             string    `json:"user"`
	Workspace        string    `json:"workspace"`
	StartTime        time.Time `json:"startTime"`
	EndTime          time.Time `json:"endTime"`
	ComputeLapse     float32   `json:"computeLapse"`
	CompletedLapse   float32   `json:"completedLapse"`
	IP               string    `json:"ip"`
	App              string    `json:"app"`
	Args             string    `json:"args"`
	Running          int64     `json:"running"`
	UCpu             int64     `json:"uCpu"`
	SCpu             int64     `json:"sCpu"`
	DiskIn           int64     `json:"diskIn"`
	DiskOut          int64     `json:"diskOut"`
	IpcIn            int64     `json:"ipcIn"`
	IpcOut           int64     `json:"ipcOut"`
	MaxRss           int64     `json:"maxRss"`
	PageFaults       int64     `json:"pageFaults"`
	RPCMsgsIn        int64     `json:"rpcMsgsIn"`
	RPCMsgsOut       int64     `json:"rpcMsgsOut"`
	RPCSizeIn        int64     `json:"rpcSizeIn"`
	RPCSizeOut       int64     `json:"rpcSizeOut"`
	RPCHimarkFwd     int64     `json:"rpcHimarkFwd"`
	RPCHimarkRev     int64     `json:"rpcHimarkRev"`
	RPCSnd           float32   `json:"rpcSnd"`
	RPCRcv           float32   `json:"rpcRcv"`
	NetFilesAdded    int64     `json:"netFilesAdded"` // Valid for syncs and network estimates records
	NetFilesUpdated  int64     `json:"netFilesUpdated"`
	NetFilesDeleted  int64     `json:"netFilesDeleted"`
	NetBytesAdded    int64     `json:"netBytesAdded"`
	NetBytesUpdated  int64     `json:"netBytesUpdated"`
	CmdError         bool      `json:"cmderror"`
	Tables           map[string]*Table
	duplicateKey     bool
	completed        bool
	countedInRunning bool
	hasTrackInfo     bool
}

// Table stores track information per table (part of Command)
type Table struct {
	TableName          string  `json:"tableName"`
	PagesIn            int64   `json:"pagesIn"`
	PagesOut           int64   `json:"pagesOut"`
	PagesCached        int64   `json:"pagesCached"`
	PagesSplitInternal int64   `json:"pagesSplitInternal"`
	PagesSplitLeaf     int64   `json:"pagesSplitLeaf"`
	ReadLocks          int64   `json:"readLocks"`
	WriteLocks         int64   `json:"writeLocks"`
	GetRows            int64   `json:"getRows"`
	PosRows            int64   `json:"posRows"`
	ScanRows           int64   `json:"scanRows"`
	PutRows            int64   `json:"putRows"`
	DelRows            int64   `json:"delRows"`
	TotalReadWait      int64   `json:"totalReadWait"`
	TotalReadHeld      int64   `json:"totalReadHeld"`
	TotalWriteWait     int64   `json:"totalWriteWait"`
	TotalWriteHeld     int64   `json:"totalWriteHeld"`
	MaxReadWait        int64   `json:"maxReadWait"`
	MaxReadHeld        int64   `json:"maxReadHeld"`
	MaxWriteWait       int64   `json:"maxWriteWait"`
	MaxWriteHeld       int64   `json:"maxWriteHeld"`
	PeekCount          int64   `json:"peekCount"`
	TotalPeekWait      int64   `json:"totalPeekWait"`
	TotalPeekHeld      int64   `json:"totalPeekHeld"`
	MaxPeekWait        int64   `json:"maxPeekWait"`
	MaxPeekHeld        int64   `json:"maxPeekHeld"`
	TriggerLapse       float32 `json:"triggerLapse"`
}

func (t *Table) setPages(pagesIn, pagesOut, pagesCached string) {
	t.PagesIn, _ = strconv.ParseInt(pagesIn, 10, 64)
	t.PagesOut, _ = strconv.ParseInt(pagesOut, 10, 64)
	t.PagesCached, _ = strconv.ParseInt(pagesCached, 10, 64)
}

func (t *Table) setPagesSplit(pagesSplitInternal, pagesSplitLeaf string) {
	t.PagesSplitInternal, _ = strconv.ParseInt(pagesSplitInternal, 10, 64)
	t.PagesSplitLeaf, _ = strconv.ParseInt(pagesSplitLeaf, 10, 64)
}

func (t *Table) setLocksRows(readLocks, writeLocks, getRows, posRows,
	scanRows, putRows, delRows string) {
	t.ReadLocks, _ = strconv.ParseInt(readLocks, 10, 64)
	t.WriteLocks, _ = strconv.ParseInt(writeLocks, 10, 64)
	t.GetRows, _ = strconv.ParseInt(getRows, 10, 64)
	t.PosRows, _ = strconv.ParseInt(posRows, 10, 64)
	t.ScanRows, _ = strconv.ParseInt(scanRows, 10, 64)
	t.PutRows, _ = strconv.ParseInt(putRows, 10, 64)
	t.DelRows, _ = strconv.ParseInt(delRows, 10, 64)
}

func (t *Table) setTotalLock(totalReadWait, totalReadHeld, totalWriteWait, totalWriteHeld string) {
	t.TotalReadWait, _ = strconv.ParseInt(totalReadWait, 10, 64)
	t.TotalReadHeld, _ = strconv.ParseInt(totalReadHeld, 10, 64)
	t.TotalWriteWait, _ = strconv.ParseInt(totalWriteWait, 10, 64)
	t.TotalWriteHeld, _ = strconv.ParseInt(totalWriteHeld, 10, 64)
}

func (t *Table) setMaxLock(maxReadWait, maxReadHeld, maxWriteWait, maxWriteHeld string) {
	t.MaxReadWait, _ = strconv.ParseInt(maxReadWait, 10, 64)
	t.MaxReadHeld, _ = strconv.ParseInt(maxReadHeld, 10, 64)
	t.MaxWriteWait, _ = strconv.ParseInt(maxWriteWait, 10, 64)
	t.MaxWriteHeld, _ = strconv.ParseInt(maxWriteHeld, 10, 64)
}

func (t *Table) setPeek(peekCount, totalPeekWait, totalPeekHeld, maxPeekWait, maxPeekHeld string) {
	t.PeekCount, _ = strconv.ParseInt(peekCount, 10, 64)
	t.TotalPeekWait, _ = strconv.ParseInt(totalPeekWait, 10, 64)
	t.TotalPeekHeld, _ = strconv.ParseInt(totalPeekHeld, 10, 64)
	t.MaxPeekWait, _ = strconv.ParseInt(maxPeekWait, 10, 64)
	t.MaxPeekHeld, _ = strconv.ParseInt(maxPeekHeld, 10, 64)
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

// GetKey - returns process key (handling duplicates)
func (c *Command) GetKey() string {
	if c.duplicateKey {
		return fmt.Sprintf("%s.%d", c.ProcessKey, c.LineNo)
	}
	return c.ProcessKey
}

func (c *Command) String() string {
	j, _ := json.Marshal(c)
	return string(j)
}

func (c *Command) setStartTime(t string) {
	c.StartTime, _ = time.Parse(p4timeformat, t)
}

func (c *Command) setEndTime(t string) {
	c.EndTime, _ = time.Parse(p4timeformat, t)
}

func (c *Command) computeEndTime() time.Time {
	if c.EndTime != blankTime {
		return c.EndTime
	}
	if c.CompletedLapse != 0.0 {
		return c.StartTime.Add(time.Duration(c.CompletedLapse) * time.Second)
	}
	return blankTime
}

// Update start and end times if we need to and we have lapse time
func (c *Command) updateStartEndTimes() {
	if c.EndTime == blankTime {
		if c.StartTime != blankTime && c.CompletedLapse != 0.0 {
			c.EndTime = c.StartTime.Add(time.Duration(c.CompletedLapse) * time.Second)
		}
	} else if c.StartTime == blankTime {
		if c.EndTime != blankTime && c.CompletedLapse != 0.0 {
			c.StartTime = c.EndTime.Add(-time.Duration(c.CompletedLapse) * time.Second)
		}
	}
}

func (c *Command) setUsage(uCPU, sCPU, diskIn, diskOut, ipcIn, ipcOut, maxRss, pageFaults string) {
	c.UCpu, _ = strconv.ParseInt(uCPU, 10, 64)
	c.SCpu, _ = strconv.ParseInt(sCPU, 10, 64)
	c.DiskIn, _ = strconv.ParseInt(diskIn, 10, 64)
	c.DiskOut, _ = strconv.ParseInt(diskOut, 10, 64)
	c.IpcIn, _ = strconv.ParseInt(ipcIn, 10, 64)
	c.IpcOut, _ = strconv.ParseInt(ipcOut, 10, 64)
	c.MaxRss, _ = strconv.ParseInt(maxRss, 10, 64)
	c.PageFaults, _ = strconv.ParseInt(pageFaults, 10, 64)
}

func (c *Command) setNetworkEstimates(netFilesAdded, netFilesUpdated, netFilesDeleted, netBytesAdded, netBytesUpdated string) {
	c.NetFilesAdded, _ = strconv.ParseInt(netFilesAdded, 10, 64)
	c.NetFilesUpdated, _ = strconv.ParseInt(netFilesUpdated, 10, 64)
	c.NetFilesDeleted, _ = strconv.ParseInt(netFilesDeleted, 10, 64)
	c.NetBytesAdded, _ = strconv.ParseInt(netBytesAdded, 10, 64)
	c.NetBytesUpdated, _ = strconv.ParseInt(netBytesUpdated, 10, 64)
}

func (c *Command) setRPC(rpcMsgsIn, rpcMsgsOut, rpcSizeIn, rpcSizeOut, rpcHimarkFwd, rpcHimarkRev, rpcSnd, rpcRcv string) {
	c.RPCMsgsIn, _ = strconv.ParseInt(rpcMsgsIn, 10, 64)
	c.RPCMsgsOut, _ = strconv.ParseInt(rpcMsgsOut, 10, 64)
	c.RPCSizeIn, _ = strconv.ParseInt(rpcSizeIn, 10, 64)
	c.RPCSizeOut, _ = strconv.ParseInt(rpcSizeOut, 10, 64)
	c.RPCHimarkFwd, _ = strconv.ParseInt(rpcHimarkFwd, 10, 64)
	c.RPCHimarkRev, _ = strconv.ParseInt(rpcHimarkRev, 10, 64)
	if rpcSnd != "" {
		f, _ := strconv.ParseFloat(rpcSnd, 32)
		c.RPCSnd = float32(f)
	}
	if rpcRcv != "" {
		f, _ := strconv.ParseFloat(rpcRcv, 32)
		c.RPCRcv = float32(f)
	}
}

// Validate table names - looking for corruptions - crept in when we were using []byte channels
func (c *Command) checkTables(msg string) {
	found := false
	var s string
	for _, t := range c.Tables {
		if strings.ContainsAny(t.TableName, " \n") {
			found = true
			s = t.TableName
			break
		}
	}
	if found {
		fmt.Fprintf(os.Stderr, "Corrupt: %s %s %d %d %s\n", msg, c.Cmd, c.Pid, c.LineNo, s)
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
		ProcessKey      string  `json:"processKey"`
		Cmd             string  `json:"cmd"`
		Pid             int64   `json:"pid"`
		LineNo          int64   `json:"lineNo"`
		User            string  `json:"user"`
		Workspace       string  `json:"workspace"`
		ComputeLapse    float32 `json:"computeLapse"`
		CompletedLapse  float32 `json:"completedLapse"`
		IP              string  `json:"ip"`
		App             string  `json:"app"`
		Args            string  `json:"args"`
		StartTime       string  `json:"startTime"`
		EndTime         string  `json:"endTime"`
		Running         int64   `json:"running"`
		UCpu            int64   `json:"uCpu"`
		SCpu            int64   `json:"sCpu"`
		DiskIn          int64   `json:"diskIn"`
		DiskOut         int64   `json:"diskOut"`
		IpcIn           int64   `json:"ipcIn"`
		IpcOut          int64   `json:"ipcOut"`
		MaxRss          int64   `json:"maxRss"`
		PageFaults      int64   `json:"pageFaults"`
		RPCMsgsIn       int64   `json:"rpcMsgsIn"`
		RPCMsgsOut      int64   `json:"rpcMsgsOut"`
		RPCSizeIn       int64   `json:"rpcSizeIn"`
		RPCSizeOut      int64   `json:"rpcSizeOut"`
		RPCHimarkFwd    int64   `json:"rpcHimarkFwd"`
		RPCHimarkRev    int64   `json:"rpcHimarkRev"`
		RPCSnd          float32 `json:"rpcSnd"`
		RPCRcv          float32 `json:"rpcRcv"`
		NetFilesAdded   int64   `json:"netFilesAdded"` // Valid for syncs and network estimates records
		NetFilesUpdated int64   `json:"netFilesUpdated"`
		NetFilesDeleted int64   `json:"netFilesDeleted"`
		NetBytesAdded   int64   `json:"netBytesAdded"`
		NetBytesUpdated int64   `json:"netBytesUpdated"`
		CmdError        bool    `json:"cmdError"`
		Tables          []Table `json:"tables"`
	}{
		ProcessKey:      c.GetKey(),
		Cmd:             c.Cmd,
		Pid:             c.Pid,
		LineNo:          c.LineNo,
		User:            c.User,
		Workspace:       c.Workspace,
		ComputeLapse:    c.ComputeLapse,
		CompletedLapse:  c.CompletedLapse,
		IP:              c.IP,
		App:             c.App,
		Args:            c.Args,
		StartTime:       c.StartTime.Format(p4timeformat),
		EndTime:         c.EndTime.Format(p4timeformat),
		Running:         c.Running,
		UCpu:            c.UCpu,
		SCpu:            c.SCpu,
		DiskIn:          c.DiskIn,
		DiskOut:         c.DiskOut,
		IpcIn:           c.IpcIn,
		IpcOut:          c.IpcOut,
		MaxRss:          c.MaxRss,
		PageFaults:      c.PageFaults,
		RPCMsgsIn:       c.RPCMsgsIn,
		RPCMsgsOut:      c.RPCMsgsOut,
		RPCSizeIn:       c.RPCSizeIn,
		RPCSizeOut:      c.RPCSizeOut,
		RPCHimarkFwd:    c.RPCHimarkFwd,
		RPCHimarkRev:    c.RPCHimarkRev,
		RPCSnd:          c.RPCSnd,
		RPCRcv:          c.RPCRcv,
		NetFilesAdded:   c.NetFilesAdded,
		NetFilesUpdated: c.NetFilesUpdated,
		NetFilesDeleted: c.NetFilesDeleted,
		NetBytesAdded:   c.NetBytesAdded,
		NetBytesUpdated: c.NetBytesUpdated,
		CmdError:        c.CmdError,
		Tables:          tables,
	})
}

var blankTime time.Time

func (c *Command) updateFrom(other *Command) {
	// The first two fields are unusual but occur when we get a completed record with no start record
	// and then get a record with track info.
	if c.StartTime == blankTime {
		c.StartTime = other.StartTime
	}
	if c.ProcessKey == "" {
		c.ProcessKey = other.ProcessKey
	}
	if c.User == "" {
		c.User = other.User
	}
	if c.Workspace == "" {
		c.Workspace = other.Workspace
	}
	if c.Cmd == "" {
		c.Cmd = other.Cmd
	}
	if c.Args == "" {
		c.Args = other.Args
	}
	if c.IP == "" {
		c.IP = other.IP
	}
	if c.App == "" {
		c.App = other.App
	}
	if c.EndTime == blankTime {
		c.EndTime = other.EndTime
	}
	// The rest are often updated
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
	if other.NetFilesAdded > 0 {
		c.NetFilesAdded = other.NetFilesAdded
	}
	if other.NetFilesDeleted > 0 {
		c.NetFilesDeleted = other.NetFilesDeleted
	}
	if other.NetFilesUpdated > 0 {
		c.NetFilesUpdated = other.NetFilesUpdated
	}
	if other.NetBytesAdded > 0 {
		c.NetBytesAdded = other.NetBytesAdded
	}
	if other.NetBytesUpdated > 0 {
		c.NetBytesUpdated = other.NetBytesUpdated
	}
	if len(other.Tables) > 0 {
		for k, t := range other.Tables {
			c.Tables[k] = t
		}
	}
}

// P4dFileParser - manages state
type P4dFileParser struct {
	logger               *logrus.Logger
	outputDuration       time.Duration
	debugDuration        time.Duration
	lineNo               int64
	m                    sync.Mutex
	cmds                 map[int64]*Command
	CmdsProcessed        int
	cmdChan              chan Command
	timeChan             chan time.Time
	linesChan            *<-chan string
	blockChan            chan *Block
	currTime             time.Time
	debug                int
	currStartTime        time.Time
	timeLastCmdProcessed time.Time
	pidsSeenThisSecond   map[int64]bool
	running              int64
	runningPids          map[int64]int64 // Maps pids to line nos
	hadServerThreadsMsg  bool
	debugPID             int64 // Set if in debug mode for a conflict
	debugCmd             string
	outputCmdsContinued  int64
	outputCmdsExited     int64
	lastSyncPID          int64
}

// NewP4dFileParser - create and initialise properly
func NewP4dFileParser(logger *logrus.Logger) *P4dFileParser {
	var fp P4dFileParser
	fp.cmds = make(map[int64]*Command)
	fp.pidsSeenThisSecond = make(map[int64]bool)
	fp.runningPids = make(map[int64]int64)
	fp.logger = logger
	fp.outputDuration = time.Second * 1
	fp.debugDuration = time.Second * 30
	return &fp
}

// SetDebugMode - turn on debugging - very verbose!
func (fp *P4dFileParser) SetDebugMode(level int) {
	fp.debug = level
}

// SetDebugPID - turn on debugging for a PID
func (fp *P4dFileParser) SetDebugPID(pid int64, cmdName string) {
	fp.debugPID = pid
	fp.debugCmd = cmdName
}

func (fp *P4dFileParser) debugLog(cmd *Command) bool {
	return cmd.Pid == fp.debugPID && cmd.Cmd == fp.debugCmd
}

// SetDurations - for debugging
func (fp *P4dFileParser) SetDurations(outputDuration, debugDuration time.Duration) {
	fp.outputDuration = outputDuration
	fp.debugDuration = debugDuration
}

func (fp *P4dFileParser) trackRunning(msg string, cmd *Command, delta int) {
	recorded := false
	if delta > 0 {
		if !cmd.countedInRunning {
			recorded = true
			fp.running++
			cmd.Running = fp.running
			cmd.countedInRunning = true
		}
	} else {
		if cmd.countedInRunning {
			recorded = true
			fp.running--
			cmd.countedInRunning = false
		}
	}
	if fp.logger == nil || fp.logger.Level < logrus.DebugLevel {
		return
	}
	// In debug mode we record and output tracks
	if delta > 0 && recorded {
		if line, ok := fp.runningPids[cmd.Pid]; !ok {
			fp.runningPids[cmd.Pid] = cmd.LineNo
		} else {
			if FlagSet(fp.debug, DebugTrackRunning) {
				fp.logger.Debugf("running-warn: unexpected cmd found line1 %d delta %d %s cmd %s pid %d line %d",
					line, delta, msg, cmd.Cmd, cmd.Pid, cmd.LineNo)
			}
		}
	} else if delta < 0 && recorded {
		if _, ok := fp.runningPids[cmd.Pid]; ok {
			delete(fp.runningPids, cmd.Pid)
		} else {
			if FlagSet(fp.debug, DebugTrackRunning) {
				fp.logger.Debugf("running-warn: unexpected cmd not found delta %d %s cmd %s pid %d line %d",
					delta, msg, cmd.Cmd, cmd.Pid, cmd.LineNo)
			}
		}
	}
	if FlagSet(fp.debug, DebugTrackRunning) {
		fp.logger.Debugf("running: %d delta %d recorded %v %s cmd %s pid %d line %d", fp.running, delta, recorded, msg, cmd.Cmd, cmd.Pid, cmd.LineNo)
	}
}

func (fp *P4dFileParser) addCommand(newCmd *Command, hasTrackInfo bool) {
	debugLog := fp.debugLog(newCmd)
	if debugLog {
		fp.logger.Infof("addCommand: hasTrack %v, pid %d lineNo %d cmd %s dup %v", hasTrackInfo, newCmd.Pid, newCmd.LineNo, newCmd.Cmd, newCmd.duplicateKey)
	}
	if fp.currTime.IsZero() || newCmd.StartTime.After(fp.currTime) {
		fp.currTime = newCmd.StartTime
	}
	newCmd.Running = fp.running
	if fp.currStartTime != newCmd.StartTime && newCmd.StartTime.After(fp.currStartTime) {
		fp.currStartTime = newCmd.StartTime
		fp.pidsSeenThisSecond = make(map[int64]bool)
	}
	if cmd, ok := fp.cmds[newCmd.Pid]; ok {
		if debugLog {
			fp.logger.Infof("addCommand found: pid %d lineNo %d cmd %s dup %v", cmd.Pid, cmd.LineNo, cmd.Cmd, cmd.duplicateKey)
		}
		if cmd.ProcessKey != "" && cmd.ProcessKey != newCmd.ProcessKey {
			if debugLog {
				fp.logger.Infof("addCommand outputting old since process key different")
			}
			fp.outputCmd(cmd)
			fp.cmds[newCmd.Pid] = newCmd // Replace previous cmd with same PID
			if !cmdHasNoCompletionRecord(newCmd.Cmd) {
				fp.trackRunning("t01", newCmd, 1)
			}
		} else if cmdHasNoCompletionRecord(newCmd.Cmd) {
			if hasTrackInfo {
				// TODO: if hasTrackInfo && !cmd.hasTrackInfo {
				cmd.updateFrom(newCmd)
			} else {
				fp.outputCmd(cmd)
				newCmd.duplicateKey = true
				fp.cmds[newCmd.Pid] = newCmd // Replace previous cmd with same PID
			}
		} else {
			// Typically track info only present when command has completed - especially for duplicates
			if cmd.hasTrackInfo {
				if cmd.LineNo == newCmd.LineNo {
					if debugLog {
						fp.logger.Infof("addCommand updating duplicate")
					}
					cmd.updateFrom(newCmd)
				} else {
					if debugLog {
						fp.logger.Infof("addCommand found duplicate - outputting old")
					}
					fp.outputCmd(cmd)
					fp.trackRunning("t02", newCmd, 1)
					newCmd.duplicateKey = true
					fp.cmds[newCmd.Pid] = newCmd // Replace previous cmd with same PID
				}
			} else {
				if debugLog {
					fp.logger.Infof("addCommand updating")
				}
				cmd.updateFrom(newCmd)
			}
		}
		if hasTrackInfo {
			if debugLog {
				fp.logger.Infof("addCommand setting hasTrackInfo")
			}
			cmd.hasTrackInfo = true
		}
	} else {
		if debugLog {
			fp.logger.Infof("addCommand remembering newCmd")
		}
		fp.cmds[newCmd.Pid] = newCmd
		if _, ok := fp.pidsSeenThisSecond[newCmd.Pid]; ok {
			newCmd.duplicateKey = true
		}
		fp.pidsSeenThisSecond[newCmd.Pid] = true
		if !cmdHasNoCompletionRecord(newCmd.Cmd) && !newCmd.completed {
			fp.trackRunning("t03", newCmd, 1)
		}
	}
	fp.outputCompletedCommands()
}

// Special commands which only have start records not completion records
func cmdHasNoCompletionRecord(cmdName string) bool {
	return cmdName == "rmt-FileFetch" ||
		cmdName == "rmt-FileFetchMulti" ||
		cmdName == "rmt-Journal" ||
		cmdName == "rmt-JournalPos" ||
		cmdName == "pull"
}

var trackStart = "---"
var trackLapse = "--- lapse "
var trackDB = "--- db."
var trackRdbLbr = "--- rdb.lbr"
var trackMeta = "--- meta"
var trackClients = "--- clients"
var trackChange = "--- change"
var trackClientEntity = "--- clientEntity"
var trackReplicaPull = "--- replica/pull"
var trackStorage = "--- storageup/"
var reCmdTrigger = regexp.MustCompile(` trigger ([^ ]+)$`)
var reTriggerLapse = regexp.MustCompile(`^lapse (\d+)s`)
var reTriggerLapse2 = regexp.MustCompile(`^lapse \.(\d+)s`)
var prefixTrackRPC = "--- rpc msgs/size in+out "
var reTrackRPC = regexp.MustCompile(`^--- rpc msgs/size in\+out (\d+)\+(\d+)/(\d+)mb\+(\d+)mb himarks (\d+)/(\d+)`)
var reTrackRPC2 = regexp.MustCompile(`^--- rpc msgs/size in\+out (\d+)\+(\d+)/(\d+)mb\+(\d+)mb himarks (\d+)/(\d+) snd/rcv ([0-9]+|[0-9]+\.[0-9]+|\.[0-9]+)s/([0-9]+|[0-9]+\.[0-9]+|\.[0-9]+)s`)
var prefixTrackUsage = "--- usage"
var reTrackUsage = regexp.MustCompile(`^--- usage (\d+)\+(\d+)us (\d+)\+(\d+)io (\d+)\+(\d+)net (\d+)k (\d+)pf`)
var reCmdUsage = regexp.MustCompile(` (\d+)\+(\d+)us (\d+)\+(\d+)io (\d+)\+(\d+)net (\d+)k (\d+)pf`)
var prefixTrackPages = "---   pages in+out+cached "
var reTrackPages = regexp.MustCompile(`^---   pages in\+out\+cached (\d+)\+(\d+)\+(\d+)`)
var prefixTrackPagesSplit = "---   pages split internal+leaf "
var reTrackPagesSplit = regexp.MustCompile(`^---   pages split internal\+leaf (\d+)\+(\d+)`)
var prefixTrackLocksRows = "---   locks read/write "
var reTrackLocksRows = regexp.MustCompile(`^---   locks read/write (\d+)/(\d+) rows get\+pos\+scan put\+del (\d+)\+(\d+)\+(\d+) (\d+)\+(\d+)`)
var prefixTrackTotalLock = "---   total lock wait+held read/write "
var reTrackTotalLock = regexp.MustCompile(`^---   total lock wait\+held read/write (\d+)ms\+(\d+)ms/(\d+)ms\+\-?(\d+)ms`)
var prefixTrackPeek = "---   peek count "
var reTrackPeek = regexp.MustCompile(`^---   peek count (\d+) wait\+held total/max (\d+)ms\+(\d+)ms/(\d+)ms\+(\d+)ms`)
var prefixTrackMaxLock = "---   max lock wait+held read/write "
var prefixTrackMaxLock2 = "---   locks wait+held read/write "
var reTrackMaxLock = regexp.MustCompile(`^---   max lock wait\+held read/write (\d+)ms\+(\d+)ms/(\d+)ms\+(\d+)ms|---   locks wait+held read/write (\d+)ms\+(\d+)ms/(\d+)ms\+(\d+)ms`)
var rePid = regexp.MustCompile(`\tPid (\d+)$`)
var prefixNetworkEstimates = "\tServer network estimates:"
var reNetworkEstimates = regexp.MustCompile(`\tServer network estimates: files added/updated/deleted=(\d+)/(\d+)/(\d+), bytes added/updated=(\d+)/(\d+)`)

func getTable(cmd *Command, tableName string) *Table {
	if _, ok := cmd.Tables[tableName]; !ok {
		cmd.Tables[tableName] = newTable(tableName)
	}
	return cmd.Tables[tableName]
}

func (fp *P4dFileParser) processTrackRecords(cmd *Command, lines []string) {
	hasTrackInfo := false
	var tableName string
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
		if strings.HasPrefix(line, trackDB) {
			tableName = string(line[len(trackDB):])
			t := newTable(tableName)
			cmd.Tables[tableName] = t
			hasTrackInfo = true
			continue
		}
		if strings.HasPrefix(line, trackRdbLbr) {
			tableName = "rdb.lbr"
			t := newTable(tableName)
			cmd.Tables[tableName] = t
			hasTrackInfo = true
			continue
		}
		if strings.HasPrefix(line, trackStorage) {
			ext := ""
			val := line[len(trackStorage):]
			j := strings.Index(val, "(R)")
			if j > 0 {
				tableName = val[:j]
				ext = "_R"
			} else {
				k := strings.Index(val, "(W)")
				if k > 0 {
					tableName = val[:k]
					ext = "_W"
				} else {
					tableName = val
				}
			}
			tableName = fmt.Sprintf("%s%s", tableName, ext)
			t := newTable(tableName)
			cmd.Tables[tableName] = t
			// Normally if we find track info we note it but this is a sppecial case since storageup
			// often output before end of command. If we note track info then we may not process end
			// record properly with the rest of the track info.
			hasTrackInfo = false
			continue
		}
		if strings.HasPrefix(line, trackMeta) ||
			strings.HasPrefix(line, trackChange) ||
			strings.HasPrefix(line, trackClients) ||
			strings.HasPrefix(line, trackClientEntity) ||
			strings.HasPrefix(line, trackReplicaPull) {
			// Special tables don't have trackInfo set
			tableName = ""
			continue
		}
		if !strings.HasPrefix(line, trackStart) {
			continue
		}
		var m []string
		if strings.HasPrefix(line, prefixTrackUsage) {
			m = reTrackUsage.FindStringSubmatch(line)
			if len(m) > 0 {
				cmd.setUsage(m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8])
				continue
			}
		}
		if strings.HasPrefix(line, prefixTrackRPC) {
			m = reTrackRPC2.FindStringSubmatch(line)
			if len(m) > 0 {
				cmd.setRPC(m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8])
				continue
			}
			m = reTrackRPC.FindStringSubmatch(line)
			if len(m) > 0 {
				cmd.setRPC(m[1], m[2], m[3], m[4], m[5], m[6], "", "")
				continue
			}
		}
		// One of the special tables - discard track records
		if len(tableName) == 0 {
			continue
		}
		// At this point entries should be: "---  rpc" or similar. If not then this is an unknown table so ignore
		if len(line) > 4 && strings.HasPrefix(line, "--- ") && line[5] != ' ' {
			tableName = ""
			if FlagSet(fp.debug, DebugUnrecognised) {
				buf := fmt.Sprintf("Unrecognised track table: %s\n", line)
				if fp.logger != nil {
					fp.logger.Tracef(buf)
				} else {
					fmt.Fprint(os.Stderr, buf)
				}
			}
			continue
		}
		if strings.HasPrefix(line, prefixTrackPages) {
			m = reTrackPages.FindStringSubmatch(line)
			if len(m) > 0 {
				t := getTable(cmd, tableName)
				t.setPages(m[1], m[2], m[3])
				continue
			}
		}
		if strings.HasPrefix(line, prefixTrackLocksRows) {
			m = reTrackLocksRows.FindStringSubmatch(line)
			if len(m) > 0 {
				t := getTable(cmd, tableName)
				t.setLocksRows(m[1], m[2], m[3], m[4], m[5], m[6], m[7])
				continue
			}
		}
		if strings.HasPrefix(line, prefixTrackTotalLock) {
			m = reTrackTotalLock.FindStringSubmatch(line)
			if len(m) > 0 {
				t := getTable(cmd, tableName)
				t.setTotalLock(m[1], m[2], m[3], m[4])
				continue
			}
		}
		if strings.HasPrefix(line, prefixTrackMaxLock) || strings.HasPrefix(line, prefixTrackMaxLock2) {
			m = reTrackMaxLock.FindStringSubmatch(line)
			if len(m) > 0 {
				t := getTable(cmd, tableName)
				t.setMaxLock(m[1], m[2], m[3], m[4])
				continue
			}
		}
		if strings.HasPrefix(line, prefixTrackPeek) {
			m = reTrackPeek.FindStringSubmatch(line)
			if len(m) > 0 {
				t := getTable(cmd, tableName)
				t.setPeek(m[1], m[2], m[3], m[4], m[5])
				continue
			}
		}
		if strings.HasPrefix(line, prefixTrackPagesSplit) {
			m = reTrackPagesSplit.FindStringSubmatch(line)
			if len(m) > 0 {
				t := getTable(cmd, tableName)
				t.setPagesSplit(m[1], m[2])
				continue
			}
		}
		if FlagSet(fp.debug, DebugUnrecognised) {
			buf := fmt.Sprintf("Unrecognised track: %s\n", string(line))
			if fp.logger != nil {
				fp.logger.Tracef(buf)
			} else {
				fmt.Fprint(os.Stderr, buf)
			}
		}

	}
	cmd.hasTrackInfo = hasTrackInfo
	fp.addCommand(cmd, hasTrackInfo)
}

// Output a single command to appropriate channel
func (fp *P4dFileParser) outputCmd(cmd *Command) {
	fp.trackRunning("t04", cmd, -1)
	if fp.debugLog(cmd) {
		fp.logger.Infof("outputting: pid %d lineNo %d cmd %s dup %v", cmd.Pid, cmd.LineNo, cmd.Cmd, cmd.duplicateKey)
	}
	cmd.updateStartEndTimes() // Required in some cases with partiall records
	// Ensure entire structure is copied, particularly map member to avoid concurrency issues
	cmdcopy := *cmd
	if cmdHasNoCompletionRecord(cmd.Cmd) {
		cmdcopy.EndTime = cmdcopy.StartTime
	}
	cmdcopy.Tables = make(map[string]*Table, len(cmd.Tables))
	i := 0
	for k, v := range cmd.Tables {
		cmdcopy.Tables[k] = v
		i++
	}
	if fp.debugLog(&cmdcopy) {
		fp.logger.Infof("outputting: computelapse %v completelapse %v endTime %s", cmdcopy.ComputeLapse,
			cmdcopy.CompletedLapse, cmdcopy.EndTime)
	}
	fp.cmdChan <- cmdcopy
	fp.CmdsProcessed++
}

// Output pending commands on debug channel if set - for debug purposes
func (fp *P4dFileParser) debugOutputCommands() {
	if !(FlagSet(fp.debug, DebugPending) || FlagSet(fp.debug, DebugPendingCounts)) || fp.logger == nil {
		return
	}
	fp.m.Lock()
	defer fp.m.Unlock()
	cmdCounter := make(map[string]int32)
	allCmdsCount := 0
	for _, cmd := range fp.cmds {
		allCmdsCount++
		cmdCounter[cmd.Cmd]++
		if FlagSet(fp.debug, DebugCommands) {
			lines := []string{}
			lines = append(lines, fmt.Sprintf("DEBUG: pid %d lineNo %d cmd %s", cmd.Pid, cmd.LineNo, cmd.Cmd))
			if len(lines) > 0 && len(lines[0]) > 0 {
				fp.logger.Trace(strings.Join(lines, `\n`))
			}
		}
	}
	if FlagSet(fp.debug, DebugPendingCounts) {
		lenCmds := len(fp.cmdChan)
		lenLines := len(*fp.linesChan)
		lenTime := len(fp.timeChan)
		lenBlocks := len(fp.blockChan)
		fmt.Fprintf(os.Stderr, "Total pending: %d, channels lines %d, cmds %d, blocks %d, time %d\n", allCmdsCount,
			lenLines, lenCmds, lenBlocks, lenTime)
		for cmd, count := range cmdCounter {
			fmt.Fprintf(os.Stderr, "%s: %d\n", cmd, count)
		}
		fmt.Fprintf(os.Stderr, "======\n")
	}
}

// Output all completed commands 3 or more seconds ago - we wait that time for possible delayed track info to come in
func (fp *P4dFileParser) outputCompletedCommands() {
	if fp.currTime.Sub(fp.timeLastCmdProcessed) < fp.outputDuration {
		fp.outputCmdsExited++
		return
	}
	fp.m.Lock()
	defer fp.m.Unlock()
	fp.outputCmdsContinued++
	cmdsToOutput := make([]*Command, 0)
	startCount := len(fp.cmds)
	const timeWindow = 3 * time.Second
	cmdHasBeenProcessed := false
	for _, cmd := range fp.cmds {
		completed := false
		debugLog := fp.debugLog(cmd)
		if cmd.completed {
			if cmd.hasTrackInfo {
				if debugLog {
					fp.logger.Infof("output: r1 pid %d lineNo %d cmd %s", cmd.Pid, cmd.LineNo, cmd.Cmd)
				}
				completed = true
			} else if !cmd.EndTime.IsZero() && fp.currStartTime.Sub(cmd.EndTime) >= timeWindow {
				if debugLog {
					fp.logger.Infof("output: r2 pid %d lineNo %d cmd %s", cmd.Pid, cmd.LineNo, cmd.Cmd)
				}
				completed = true
			} else if !fp.timeLastCmdProcessed.IsZero() && fp.currTime.Sub(fp.timeLastCmdProcessed) >= timeWindow {
				if debugLog {
					fp.logger.Infof("output: r3 pid %d lineNo %d cmd %s currT %s tlcp %s", cmd.Pid, cmd.LineNo, cmd.Cmd, fp.currTime, fp.timeLastCmdProcessed)
				}
				completed = true
			}
		}
		// We have observed logs with very few "completed" records.
		if !completed && (cmd.hasTrackInfo && cmd.computeEndTime() != blankTime &&
			fp.currStartTime.Sub(cmd.computeEndTime()) >= timeWindow) {
			if debugLog {
				fp.logger.Infof("output: r4 pid %d lineNo %d cmd %s", cmd.Pid, cmd.LineNo, cmd.Cmd)
			}
			completed = true
		}
		// Handle the special commands which don't receive a completed time - we use StartTime
		if !completed && fp.currStartTime.Sub(cmd.StartTime) >= timeWindow && cmdHasNoCompletionRecord(cmd.Cmd) {
			if debugLog {
				fp.logger.Infof("output: r5 pid %d lineNo %d cmd %s", cmd.Pid, cmd.LineNo, cmd.Cmd)
			}
			completed = true
		}
		if completed {
			cmdHasBeenProcessed = true
			cmdsToOutput = append(cmdsToOutput, cmd)
			delete(fp.cmds, cmd.Pid)
		}
	}
	// Sort by line no in log and output
	sort.Slice(cmdsToOutput[:], func(i, j int) bool {
		return cmdsToOutput[i].LineNo < cmdsToOutput[j].LineNo
	})
	for _, cmd := range cmdsToOutput {
		fp.outputCmd(cmd)
	}

	if cmdHasBeenProcessed || fp.timeLastCmdProcessed == blankTime {
		fp.timeLastCmdProcessed = fp.currTime
	}
	if fp.logger != nil && fp.debug > 0 {
		endCount := len(fp.cmds)
		fp.logger.Debugf("outputCompletedCommands: start %d, end %d, count %d, continued %d, exited %d",
			startCount, endCount, startCount-endCount, fp.outputCmdsContinued, fp.outputCmdsExited)
	}
}

// Processes all remaining commands whether completed or not - intended for use at end of processing
func (fp *P4dFileParser) outputRemainingCommands() {
	startCount := len(fp.cmds)
	for _, cmd := range fp.cmds {
		fp.outputCmd(cmd)
	}
	fp.cmds = make(map[int64]*Command)
	if fp.logger != nil && fp.debug > 0 {
		endCount := len(fp.cmds)
		fp.logger.Debugf("outputRemainingCommands: start %d, end %d, count %d",
			startCount, endCount, startCount-endCount)
	}
}

func (fp *P4dFileParser) updateComputeTime(pid int64, computeLapse string) {
	if cmd, ok := fp.cmds[pid]; ok {
		// sum all compute values for same command
		f, _ := strconv.ParseFloat(string(computeLapse), 32)
		cmd.ComputeLapse = cmd.ComputeLapse + float32(f)
		if cmd.Cmd == "user-sync" {
			fp.lastSyncPID = cmd.Pid
		}
	}

}

func (fp *P4dFileParser) updateCompletionTime(pid int64, lineNo int64, endTime string, completedLapse string) {
	if cmd, ok := fp.cmds[pid]; ok {
		cmd.setEndTime(endTime)
		f, _ := strconv.ParseFloat(string(completedLapse), 32)
		cmd.CompletedLapse = float32(f)
		cmd.completed = true
		fp.trackRunning("t05", cmd, -1)
	} else {
		// This is a completion record for an unknown cmd start - maybe previous log file
		// We create a new command because there may be a track record along soon with more info
		cmd = newCommand()
		cmd.Pid = pid
		cmd.LineNo = lineNo
		cmd.setEndTime(endTime)
		f, _ := strconv.ParseFloat(string(completedLapse), 32)
		cmd.CompletedLapse = float32(f)
		cmd.completed = true
		fp.addCommand(cmd, false)
	}
}

func (fp *P4dFileParser) updateUsage(pid int64, uCPU, sCPU, diskIn, diskOut, ipcIn, ipcOut, maxRss, pageFaults string) {
	if cmd, ok := fp.cmds[pid]; ok {
		cmd.setUsage(uCPU, sCPU, diskIn, diskOut, ipcIn, ipcOut, maxRss, pageFaults)
	}
}

func (fp *P4dFileParser) updateNetworkEstimates(pid int64, netFilesAdded, netFilesUpdated,
	netFilesDeleted, netBytesAdded, netBytesUpdated string) {
	if cmd, ok := fp.cmds[pid]; ok {
		cmd.setNetworkEstimates(netFilesAdded, netFilesUpdated, netFilesDeleted, netBytesAdded, netBytesUpdated)
	}
}

func (fp *P4dFileParser) processTriggerLapse(cmd *Command, trigger string, line string) {
	// Expects a single line with a lapse statement on it
	var triggerLapse float64
	m := reTriggerLapse.FindStringSubmatch(line)
	if len(m) > 0 {
		triggerLapse, _ = strconv.ParseFloat(string(m[1]), 32)
	} else {
		m = reTriggerLapse2.FindStringSubmatch(line)
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

	// These blocks are matched with a previous sync block (usually compute entry)
	if len(block.lines) == 1 && strings.HasPrefix(block.lines[0], prefixNetworkEstimates) {
		m := reNetworkEstimates.FindStringSubmatch(block.lines[0])
		if len(m) > 0 {
			fp.updateNetworkEstimates(fp.lastSyncPID, m[1], m[2], m[3], m[4], m[5])
		}
		return
	}

	i := 0
	inMultiLineDesc := false
	for _, line := range block.lines {
		if cmd != nil && strings.HasPrefix(line, trackStart) {
			fp.processTrackRecords(cmd, block.lines[i:])
			return // Block has been processed
		}
		i++

		matched := false
		m := reCmd.FindStringSubmatch(line)
		if len(m) == 0 {
			m = reCmdNoarg.FindStringSubmatch(line)
		}
		if len(m) == 0 {
			m = reCmdMultiLineDesc.FindStringSubmatch(line)
			if len(m) > 0 {
				inMultiLineDesc = true
			}
		}
		if len(m) > 0 {
			matched = true
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
				cmd.Args = string(m[8])
				// Strip Swarm/Git Fusion commands with lots of json
				sm := reJSONCmdargs.FindStringSubmatch(cmd.Args)
				if len(sm) > 0 {
					cmd.Args = string(sm[1])
				}
			}
			// Detect multine descriptions - check if trailing quote found
			if inMultiLineDesc {
				if i := strings.Index(block.lines[len(block.lines)-1], "'"); i < 0 {
					buf := fmt.Sprintf("Unrecognised multiline description: %s\n%s\n", string(line),
						block.lines[len(block.lines)-1])
					if fp.logger != nil {
						fp.logger.Warn(buf)
					}
				}
			}
			// Detect trigger entries
			trigger := ""
			if i := strings.Index(line, "' trigger "); i >= 0 {
				tm := reCmdTrigger.FindStringSubmatch(line[i:])
				if len(tm) > 0 {
					trigger = string(tm[1])
				}
				line = line[:i+1] // Strip from the line
			}
			// Detect slightly strange IDLE commands
			if i := strings.Index(line, "' exited unexpectedly, removed from monitor table."); i >= 0 {
				if cmd.Cmd == "IDLE" {
					return
				}
			}
			h := md5.Sum([]byte(line))
			cmd.ProcessKey = hex.EncodeToString(h[:])
			if len(trigger) > 0 {
				fp.processTriggerLapse(cmd, trigger, block.lines[len(block.lines)-1])
			}
			fp.addCommand(cmd, false)
		}
		if !matched {
			// process completed and computed
			var pid int64
			m := reCompleted.FindStringSubmatch(line)
			if len(m) > 0 {
				matched = true
				endTime := m[1]
				pid = toInt64(m[2])
				completedLapse := m[3]
				fp.updateCompletionTime(pid, block.lineNo, endTime, completedLapse)
			}
			// Note cmd completion also has usage data potentially
			if matched {
				m = reCmdUsage.FindStringSubmatch(line)
				if len(m) > 0 {
					fp.updateUsage(pid, m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8])
				}
			}
		}
		if !matched {
			m := reCompute.FindStringSubmatch(line)
			if len(m) > 0 {
				matched = true
				pid := toInt64(m[2])
				computeLapse := m[3]
				fp.updateComputeTime(pid, computeLapse)
			}
		}
		if !matched && FlagSet(fp.debug, DebugUnrecognised) {
			if !strings.HasPrefix(line, "server to client") {
				buf := fmt.Sprintf("Unrecognised: %s\n", string(line))
				if fp.logger != nil {
					fp.logger.Trace(buf)
				} else {
					fmt.Fprint(os.Stderr, buf)
				}
			}
		}

	}
}

func (fp *P4dFileParser) processErrorBlock(block *Block) {
	var cmd *Command
	for _, line := range block.lines {
		m := rePid.FindStringSubmatch(line)
		if len(m) > 0 {
			pid := toInt64(m[1])
			ok := false
			if cmd, ok = fp.cmds[pid]; ok {
				cmd.CmdError = true
				cmd.completed = true
				if !cmdHasNoCompletionRecord(cmd.Cmd) {
					fp.trackRunning("t06", cmd, -1)
				}
			}
			return
		}
	}
}

func (fp *P4dFileParser) processServerThreadsBlock(block *Block) {
	if fp.hadServerThreadsMsg { // Only do once
		return
	}
	fp.hadServerThreadsMsg = true
	line := block.lines[0]
	m := reServerThreads.FindStringSubmatch(line)
	if len(m) > 0 {
		i, err := strconv.ParseInt(m[2], 10, 64)
		if err == nil {
			fp.running = i
			fp.logger.Infof("Resetting running to %d as encountered server threads message", i)
		}
	}
}

func (fp *P4dFileParser) processBlock(block *Block) {
	if block.btype == infoType {
		fp.processInfoBlock(block)
	} else if block.btype == activeThreadsType {
		fp.processServerThreadsBlock(block)
	} else if block.btype == errorType {
		fp.processErrorBlock(block)
	} //TODO: output unrecognised block if wanted
}

func blankLine(line string) bool {
	return len(line) == 0
}

var blockEnds = []string{
	"Perforce server info:",
	"Perforce server error:",
	"locks acquired by blocking after",
	"Rpc himark:",
	"server to client"}

var msgActiveThreads = " active threads."
var reServerThreads = regexp.MustCompile(`^\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d \d+ pid (\d+): Server is now using (\d+) active threads.`)

func blockEnd(line string) bool {
	if blankLine(line) {
		return true
	}
	for _, str := range blockEnds {
		if line == str {
			return true
		}
	}
	if strings.HasSuffix(line, msgActiveThreads) { // OK to do a regex as does occur frequently
		if m := reServerThreads.FindStringSubmatch(line); len(m) > 0 {
			return true
		}
	}
	return false
}

// CmdsPendingCount - count of unmatched commands
func (fp *P4dFileParser) CmdsPendingCount() int {
	fp.m.Lock()
	defer fp.m.Unlock()
	return len(fp.cmds)
}

// LogParser - interface to be run on a go routine - commands are returned on cmdchan
func (fp *P4dFileParser) LogParser(ctx context.Context, linesChan <-chan string, timeChan <-chan time.Time) chan Command {
	fp.lineNo = 1

	fp.cmdChan = make(chan Command, 10000)
	fp.linesChan = &linesChan
	fp.blockChan = make(chan *Block, 1000)

	// Commands are output on a seperate thread
	// timeChan is nil when there are no metrics to process.
	// We need to consume events on timeChan to avoid blocking other processes
	if timeChan == nil {
		ticker := time.NewTicker(fp.outputDuration)
		tickerDebug := time.NewTicker(fp.debugDuration)
		go func() {
			for {
				select {
				case t, _ := <-ticker.C:
					fp.m.Lock()
					fp.currTime = t
					fp.m.Unlock()
				case <-tickerDebug.C:
					fp.debugOutputCommands()
				}
			}
		}()
	} else {
		go func() {
			tickerDebug := time.NewTicker(fp.debugDuration)
			for {
				select {
				case t, ok := <-timeChan:
					if ok {
						fp.m.Lock()
						fp.currTime = t
						fp.m.Unlock()
					} else {
						return
					}
				case <-tickerDebug.C:
					fp.debugOutputCommands()
				}
			}
		}()
	}

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
						block.addLine(line, fp.lineNo)
					} else {
						block.addLine(line, fp.lineNo)
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
				fp.outputRemainingCommands()
				return
			case b, ok := <-fp.blockChan:
				if ok {
					fp.processBlock(b)
					if fp.running > maxRunningCount {
						panic(fmt.Sprintf("ERROR: max running command limit (%d) exceeded. Does this server log have completion records configured (configurable server=3)?",
							maxRunningCount))
					}
				} else {
					fp.outputRemainingCommands()
					return
				}
			}
		}
	}()

	return fp.cmdChan
}
