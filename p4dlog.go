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
// Note a panic is raised telling the user what to do!
// In future we may allow this to be set by parameter if required.
const maxRunningCount = 20000

// DebugLevel - for different levels of debugging
type DebugLevel int

const (
	DebugBasic DebugLevel = 1 << iota
	DebugDatabase
	DebugJSON
	DebugCommands
	DebugAddCommands
	DebugTrackRunning
	DebugUnrecognised
	DebugPending
	DebugPendingCounts
	DebugTrackPaused
	DebugMetricStats
	DebugLines
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
		} else if strings.HasSuffix(line, msgActiveThreads) {
			block.btype = activeThreadsType
			block.lines = append(block.lines, line)
		} else if strings.HasSuffix(line, msgPausedThreads) {
			block.btype = pausedThreadsType
			block.lines = append(block.lines, line)
		} else if strings.Contains(line, msgResourcePressure) {
			block.btype = resourcePressureType
			block.lines = append(block.lines, line)
		} else {
			block.btype = errorType
		}
		return
	}
	block.lines = append(block.lines, line)
}

// ServerEvent
type ServerEvent struct {
	EventTime        time.Time `json:"eventTime"`
	LineNo           int64     `json:"lineNo"`
	ActiveThreads    int64     `json:"activeThreads"`
	ActiveThreadsMax int64     `json:"activeThreadsMax"`
	PausedThreads    int64     `json:"pausedThreads"`
	PausedThreadsMax int64     `json:"pausedThreadsMax"`
	PausedErrorCount int64     `json:"pausedErrorCount"`
	PauseRateCPU     int64     `json:"pauseRateCPU"`     // Percentage 1-100
	PauseRateMem     int64     `json:"pauseRateMem"`     // Percentage 1-100
	CPUPressureState int64     `json:"cpuPressureState"` // 0-2
	MemPressureState int64     `json:"memPressureState"` // 0-2
}

func (s *ServerEvent) String() string {
	j, _ := json.Marshal(s)
	return string(j)
}

// Command is a command found in the block
type Command struct {
	ProcessKey              string    `json:"processKey"`
	Cmd                     string    `json:"cmd"`
	Pid                     int64     `json:"pid"`
	LineNo                  int64     `json:"lineNo"`
	User                    string    `json:"user"`
	Workspace               string    `json:"workspace"`
	StartTime               time.Time `json:"startTime"`
	EndTime                 time.Time `json:"endTime"`
	ComputeLapse            float32   `json:"computeLapse"`
	CompletedLapse          float32   `json:"completedLapse"`
	Paused                  float32   `json:"paused"` // How long command was paused
	IP                      string    `json:"ip"`
	App                     string    `json:"app"`
	Args                    string    `json:"args"`
	Running                 int64     `json:"running"`
	UCpu                    int64     `json:"uCpu"`
	SCpu                    int64     `json:"sCpu"`
	DiskIn                  int64     `json:"diskIn"`
	DiskOut                 int64     `json:"diskOut"`
	IpcIn                   int64     `json:"ipcIn"`
	IpcOut                  int64     `json:"ipcOut"`
	MaxRss                  int64     `json:"maxRss"`
	PageFaults              int64     `json:"pageFaults"`
	MemMB                   int64     `json:"memMB"`
	MemPeakMB               int64     `json:"memPeakMB"`
	RPCMsgsIn               int64     `json:"rpcMsgsIn"`
	RPCMsgsOut              int64     `json:"rpcMsgsOut"`
	RPCSizeIn               int64     `json:"rpcSizeIn"`
	RPCSizeOut              int64     `json:"rpcSizeOut"`
	RPCHimarkFwd            int64     `json:"rpcHimarkFwd"`
	RPCHimarkRev            int64     `json:"rpcHimarkRev"`
	RPCSnd                  float32   `json:"rpcSnd"`
	RPCRcv                  float32   `json:"rpcRcv"`
	FileTotalsSnd           int64     `json:"fileTotalsSnd`
	FileTotalsRcv           int64     `json:"fileTotalsRcv`
	FileTotalsSndMBytes     int64     `json:"fileTotalsSndMBytes`
	FileTotalsRcvMBytes     int64     `json:"fileTotalsRcvMBytes`
	NetFilesAdded           int64     `json:"netFilesAdded"` // Valid for syncs and network estimates records
	NetFilesUpdated         int64     `json:"netFilesUpdated"`
	NetFilesDeleted         int64     `json:"netFilesDeleted"`
	NetBytesAdded           int64     `json:"netBytesAdded"`
	NetBytesUpdated         int64     `json:"netBytesUpdated"`
	LbrRcsOpens             int64     `json:"lbrRcsOpens"` // Required for processing lbr records
	LbrRcsCloses            int64     `json:"lbrRcsCloses"`
	LbrRcsCheckins          int64     `json:"lbrRcsCheckins"`
	LbrRcsExists            int64     `json:"lbrRcsExists"`
	LbrRcsReads             int64     `json:"lbrRcsReads"`
	LbrRcsReadBytes         int64     `json:"lbrRcsReadBytes"`
	LbrRcsWrites            int64     `json:"lbrRcsWrites"`
	LbrRcsWriteBytes        int64     `json:"lbrRcsWriteBytes"`
	LbrRcsDigests           int64     `json:"lbrRcsDigests"`
	LbrRcsFileSizes         int64     `json:"lbrRcsFileSizes"`
	LbrRcsModTimes          int64     `json:"lbrRcsModTimes"`
	LbrRcsCopies            int64     `json:"lbrRcsCopies"`
	LbrBinaryOpens          int64     `json:"lbrBinaryOpens"`
	LbrBinaryCloses         int64     `json:"lbrBinaryCloses"`
	LbrBinaryCheckins       int64     `json:"lbrBinaryCheckins"`
	LbrBinaryExists         int64     `json:"lbrBinaryExists"`
	LbrBinaryReads          int64     `json:"lbrBinaryReads"`
	LbrBinaryReadBytes      int64     `json:"lbrBinaryReadBytes"`
	LbrBinaryWrites         int64     `json:"lbrBinaryWrites"`
	LbrBinaryWriteBytes     int64     `json:"lbrBinaryWriteBytes"`
	LbrBinaryDigests        int64     `json:"lbrBinaryDigests"`
	LbrBinaryFileSizes      int64     `json:"lbrBinaryFileSizes"`
	LbrBinaryModTimes       int64     `json:"lbrBinaryModTimes"`
	LbrBinaryCopies         int64     `json:"lbrBinaryCopies"`
	LbrCompressOpens        int64     `json:"lbrCompressOpens"`
	LbrCompressCloses       int64     `json:"lbrCompressCloses"`
	LbrCompressCheckins     int64     `json:"lbrCompressCheckins"`
	LbrCompressExists       int64     `json:"lbrCompressExists"`
	LbrCompressReads        int64     `json:"lbrCompressReads"`
	LbrCompressReadBytes    int64     `json:"lbrCompressReadBytes"`
	LbrCompressWrites       int64     `json:"lbrCompressWrites"`
	LbrCompressWriteBytes   int64     `json:"lbrCompressWriteBytes"`
	LbrCompressDigests      int64     `json:"lbrCompressDigests"`
	LbrCompressFileSizes    int64     `json:"lbrCompressFileSizes"`
	LbrCompressModTimes     int64     `json:"lbrCompressModTimes"`
	LbrCompressCopies       int64     `json:"lbrCompressCopies"`
	LbrUncompressOpens      int64     `json:"lbrUncompressOpens"`
	LbrUncompressCloses     int64     `json:"lbrUncompressCloses"`
	LbrUncompressCheckins   int64     `json:"lbrUncompressCheckins"`
	LbrUncompressExists     int64     `json:"lbrUncompressExists"`
	LbrUncompressReads      int64     `json:"lbrUncompressReads"`
	LbrUncompressReadBytes  int64     `json:"lbrUncompressReadBytes"`
	LbrUncompressWrites     int64     `json:"lbrUncompressWrites"`
	LbrUncompressWriteBytes int64     `json:"lbrUncompressWriteBytes"`
	LbrUncompressDigests    int64     `json:"lbrUncompressDigests"`
	LbrUncompressFileSizes  int64     `json:"lbrUncompressFileSizes"`
	LbrUncompressModTimes   int64     `json:"lbrUncompressModTimes"`
	LbrUncompressCopies     int64     `json:"lbrUncompressCopies"`
	CmdError                bool      `json:"cmderror"`
	Tables                  map[string]*Table
	duplicateKey            bool
	completed               bool
	countedInRunning        bool
	hasTrackInfo            bool
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

func (c *Command) setMem(memMB, memPeakMB string) {
	c.MemMB, _ = strconv.ParseInt(memMB, 10, 64)
	c.MemPeakMB, _ = strconv.ParseInt(memPeakMB, 10, 64)
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

func (c *Command) setFileTotals(fileTotalsSnd, fileTotalsSndMBytes, fileTotalsRcv, fileTotalsRcvMBytes string) {
	c.FileTotalsSnd, _ = strconv.ParseInt(fileTotalsSnd, 10, 64)
	c.FileTotalsSndMBytes, _ = strconv.ParseInt(fileTotalsSndMBytes, 10, 64)
	c.FileTotalsRcv, _ = strconv.ParseInt(fileTotalsRcv, 10, 64)
	c.FileTotalsRcvMBytes, _ = strconv.ParseInt(fileTotalsRcvMBytes, 10, 64)
}

func (c *Command) setLbrRcsOpensCloses(lbrOpens, lbrCloses, lbrCheckins, lbrExists string) {
	if lbrOpens != "" {
		c.LbrRcsOpens, _ = strconv.ParseInt(lbrOpens, 10, 64)
	}
	if lbrCloses != "" {
		c.LbrRcsCloses, _ = strconv.ParseInt(lbrCloses, 10, 64)
	}
	if lbrCheckins != "" {
		c.LbrRcsCheckins, _ = strconv.ParseInt(lbrCheckins, 10, 64)
	}
	if lbrExists != "" {
		c.LbrRcsExists, _ = strconv.ParseInt(lbrExists, 10, 64)
	}
}

func (c *Command) setLbrRcsReadWrites(lbrReads, lbrWrites string, lbrReadBytes, lbrWriteBytes int64) {
	if lbrReads != "" {
		c.LbrRcsReads, _ = strconv.ParseInt(lbrReads, 10, 64)
	}
	if lbrWrites != "" {
		c.LbrRcsWrites, _ = strconv.ParseInt(lbrWrites, 10, 64)
	}
	c.LbrRcsReadBytes = lbrReadBytes
	c.LbrRcsWriteBytes = lbrWriteBytes
}

func (c *Command) setLbrRcsDigestFilesizes(digests, filesizez, modtimes, copies string) {
	if digests != "" {
		c.LbrRcsDigests, _ = strconv.ParseInt(digests, 10, 64)
	}
	if filesizez != "" {
		c.LbrRcsFileSizes, _ = strconv.ParseInt(filesizez, 10, 64)
	}
	if modtimes != "" {
		c.LbrRcsModTimes, _ = strconv.ParseInt(modtimes, 10, 64)
	}
	if copies != "" {
		c.LbrRcsCopies, _ = strconv.ParseInt(copies, 10, 64)
	}
}

func (c *Command) setLbrBinaryOpensCloses(lbrOpens, lbrCloses, lbrCheckins, lbrExists string) {
	if lbrOpens != "" {
		c.LbrBinaryOpens, _ = strconv.ParseInt(lbrOpens, 10, 64)
	}
	if lbrCloses != "" {
		c.LbrBinaryCloses, _ = strconv.ParseInt(lbrCloses, 10, 64)
	}
	if lbrCheckins != "" {
		c.LbrBinaryCheckins, _ = strconv.ParseInt(lbrCheckins, 10, 64)
	}
	if lbrExists != "" {
		c.LbrBinaryExists, _ = strconv.ParseInt(lbrExists, 10, 64)
	}
}

func (c *Command) setLbrBinaryReadWrites(lbrReads, lbrWrites string, lbrReadBytes, lbrWriteBytes int64) {
	if lbrReads != "" {
		c.LbrBinaryReads, _ = strconv.ParseInt(lbrReads, 10, 64)
	}
	if lbrWrites != "" {
		c.LbrBinaryWrites, _ = strconv.ParseInt(lbrWrites, 10, 64)
	}
	c.LbrBinaryReadBytes = lbrReadBytes
	c.LbrBinaryWriteBytes = lbrWriteBytes
}

func (c *Command) setLbrBinaryDigestFilesizes(digests, filesizez, modtimes, copies string) {
	if digests != "" {
		c.LbrBinaryDigests, _ = strconv.ParseInt(digests, 10, 64)
	}
	if filesizez != "" {
		c.LbrBinaryFileSizes, _ = strconv.ParseInt(filesizez, 10, 64)
	}
	if modtimes != "" {
		c.LbrBinaryModTimes, _ = strconv.ParseInt(modtimes, 10, 64)
	}
	if copies != "" {
		c.LbrBinaryCopies, _ = strconv.ParseInt(copies, 10, 64)
	}
}

func (c *Command) setLbrCompressOpensCloses(lbrOpens, lbrCloses, lbrCheckins, lbrExists string) {
	if lbrOpens != "" {
		c.LbrCompressOpens, _ = strconv.ParseInt(lbrOpens, 10, 64)
	}
	if lbrCloses != "" {
		c.LbrCompressCloses, _ = strconv.ParseInt(lbrCloses, 10, 64)
	}
	if lbrCheckins != "" {
		c.LbrCompressCheckins, _ = strconv.ParseInt(lbrCheckins, 10, 64)
	}
	if lbrExists != "" {
		c.LbrCompressExists, _ = strconv.ParseInt(lbrExists, 10, 64)
	}
}

func (c *Command) setLbrCompressReadWrites(lbrReads, lbrWrites string, lbrReadBytes, lbrWriteBytes int64) {
	if lbrReads != "" {
		c.LbrCompressReads, _ = strconv.ParseInt(lbrReads, 10, 64)
	}
	if lbrWrites != "" {
		c.LbrCompressWrites, _ = strconv.ParseInt(lbrWrites, 10, 64)
	}
	c.LbrCompressReadBytes = lbrReadBytes
	c.LbrCompressWriteBytes = lbrWriteBytes
}

func (c *Command) setLbrCompressDigestFilesizes(digests, filesizez, modtimes, copies string) {
	if digests != "" {
		c.LbrCompressDigests, _ = strconv.ParseInt(digests, 10, 64)
	}
	if filesizez != "" {
		c.LbrCompressFileSizes, _ = strconv.ParseInt(filesizez, 10, 64)
	}
	if modtimes != "" {
		c.LbrCompressModTimes, _ = strconv.ParseInt(modtimes, 10, 64)
	}
	if copies != "" {
		c.LbrCompressCopies, _ = strconv.ParseInt(copies, 10, 64)
	}
}

func (c *Command) setLbrUncompressOpensCloses(lbrOpens, lbrCloses, lbrCheckins, lbrExists string) {
	if lbrOpens != "" {
		c.LbrUncompressOpens, _ = strconv.ParseInt(lbrOpens, 10, 64)
	}
	if lbrCloses != "" {
		c.LbrUncompressCloses, _ = strconv.ParseInt(lbrCloses, 10, 64)
	}
	if lbrCheckins != "" {
		c.LbrUncompressCheckins, _ = strconv.ParseInt(lbrCheckins, 10, 64)
	}
	if lbrExists != "" {
		c.LbrUncompressExists, _ = strconv.ParseInt(lbrExists, 10, 64)
	}
}

func (c *Command) setLbrUncompressReadWrites(lbrReads, lbrWrites string, lbrReadBytes, lbrWriteBytes int64) {
	if lbrReads != "" {
		c.LbrUncompressReads, _ = strconv.ParseInt(lbrReads, 10, 64)
	}
	if lbrWrites != "" {
		c.LbrUncompressWrites, _ = strconv.ParseInt(lbrWrites, 10, 64)
	}
	c.LbrUncompressReadBytes = lbrReadBytes
	c.LbrUncompressWriteBytes = lbrWriteBytes
}

func (c *Command) setLbrUncompressDigestFilesizes(digests, filesizez, modtimes, copies string) {
	if digests != "" {
		c.LbrUncompressDigests, _ = strconv.ParseInt(digests, 10, 64)
	}
	if filesizez != "" {
		c.LbrUncompressFileSizes, _ = strconv.ParseInt(filesizez, 10, 64)
	}
	if modtimes != "" {
		c.LbrUncompressModTimes, _ = strconv.ParseInt(modtimes, 10, 64)
	}
	if copies != "" {
		c.LbrUncompressCopies, _ = strconv.ParseInt(copies, 10, 64)
	}
}

// MarshalJSON - handle formatting
func (s *ServerEvent) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		EventTime        time.Time `json:"eventTime"`
		LineNo           int64     `json:"lineNo"`
		ActiveThreads    int64     `json:"activeThreads"`
		ActiveThreadsMax int64     `json:"activeThreadsMax"`
		PausedThreads    int64     `json:"pausedThreads"`
		PausedThreadsMax int64     `json:"pausedThreadsMax"`
		PausedErrorCount int64     `json:"pausedErrorCount"`
		PauseRateCPU     int64     `json:"pauseRateCPU"`     // Percentage 1-100
		PauseRateMem     int64     `json:"pauseRateMem"`     // Percentage 1-100
		CPUPressureState int64     `json:"cpuPressureState"` // 0-2
		MemPressureState int64     `json:"memPressureState"` // 0-2
	}{
		EventTime:        s.EventTime,
		LineNo:           s.LineNo,
		ActiveThreads:    s.ActiveThreads,
		ActiveThreadsMax: s.ActiveThreadsMax,
		PausedThreads:    s.PausedThreads,
		PausedThreadsMax: s.PausedThreadsMax,
		PausedErrorCount: s.PausedErrorCount,
		PauseRateCPU:     s.PauseRateCPU,
		PauseRateMem:     s.PauseRateMem,
		CPUPressureState: s.CPUPressureState,
		MemPressureState: s.MemPressureState,
	})
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
		ProcessKey              string  `json:"processKey"`
		Cmd                     string  `json:"cmd"`
		Pid                     int64   `json:"pid"`
		LineNo                  int64   `json:"lineNo"`
		User                    string  `json:"user"`
		Workspace               string  `json:"workspace"`
		ComputeLapse            float32 `json:"computeLapse"`
		CompletedLapse          float32 `json:"completedLapse"`
		Paused                  float32 `json:"paused"`
		IP                      string  `json:"ip"`
		App                     string  `json:"app"`
		Args                    string  `json:"args"`
		StartTime               string  `json:"startTime"`
		EndTime                 string  `json:"endTime"`
		Running                 int64   `json:"running"`
		UCpu                    int64   `json:"uCpu"`
		SCpu                    int64   `json:"sCpu"`
		DiskIn                  int64   `json:"diskIn"`
		DiskOut                 int64   `json:"diskOut"`
		IpcIn                   int64   `json:"ipcIn"`
		IpcOut                  int64   `json:"ipcOut"`
		MaxRss                  int64   `json:"maxRss"`
		PageFaults              int64   `json:"pageFaults"`
		MemMB                   int64   `json:"memMB"`
		MemPeakMB               int64   `json:"memPeakMB"`
		RPCMsgsIn               int64   `json:"rpcMsgsIn"`
		RPCMsgsOut              int64   `json:"rpcMsgsOut"`
		RPCSizeIn               int64   `json:"rpcSizeIn"`
		RPCSizeOut              int64   `json:"rpcSizeOut"`
		RPCHimarkFwd            int64   `json:"rpcHimarkFwd"`
		RPCHimarkRev            int64   `json:"rpcHimarkRev"`
		RPCSnd                  float32 `json:"rpcSnd"`
		RPCRcv                  float32 `json:"rpcRcv"`
		FileTotalsSnd           int64   `json:"fileTotalsSnd"`       // Valid for syncs
		FileTotalsRcv           int64   `json:"fileTotalsRcv"`       // Valid for syncs
		FileTotalsSndMBytes     int64   `json:"fileTotalsSndMBytes"` // Valid for syncs
		FileTotalsRcvMBytes     int64   `json:"fileTotalsRcvMBytes"` // Valid for syncs
		NetFilesAdded           int64   `json:"netFilesAdded"`       // Valid for syncs and network estimates records
		NetFilesUpdated         int64   `json:"netFilesUpdated"`
		NetFilesDeleted         int64   `json:"netFilesDeleted"`
		NetBytesAdded           int64   `json:"netBytesAdded"`
		NetBytesUpdated         int64   `json:"netBytesUpdated"`
		LbrRcsOpens             int64   `json:"lbrRcsOpens"` // Required for processing lbr records
		LbrRcsCloses            int64   `json:"lbrRcsCloses"`
		LbrRcsCheckins          int64   `json:"lbrRcsCheckins"`
		LbrRcsExists            int64   `json:"lbrRcsExists"`
		LbrRcsReads             int64   `json:"lbrRcsReads"`
		LbrRcsReadBytes         int64   `json:"lbrRcsReadBytes"`
		LbrRcsWrites            int64   `json:"lbrRcsWrites"`
		LbrRcsWriteBytes        int64   `json:"lbrRcsWriteBytes"`
		LbrRcsDigests           int64   `json:"lbrRcsDigests"`
		LbrRcsFileSizes         int64   `json:"lbrRcsFileSizes"`
		LbrRcsModTimes          int64   `json:"lbrRcsModTimes"`
		LbrRcsCopies            int64   `json:"lbrRcsCopies"`
		LbrBinaryOpens          int64   `json:"lbrBinaryOpens"`
		LbrBinaryCloses         int64   `json:"lbrBinaryCloses"`
		LbrBinaryCheckins       int64   `json:"lbrBinaryCheckins"`
		LbrBinaryExists         int64   `json:"lbrBinaryExists"`
		LbrBinaryReads          int64   `json:"lbrBinaryReads"`
		LbrBinaryReadBytes      int64   `json:"lbrBinaryReadBytes"`
		LbrBinaryWrites         int64   `json:"lbrBinaryWrites"`
		LbrBinaryWriteBytes     int64   `json:"lbrBinaryWriteBytes"`
		LbrBinaryDigests        int64   `json:"lbrBinaryDigests"`
		LbrBinaryFileSizes      int64   `json:"lbrBinaryFileSizes"`
		LbrBinaryModTimes       int64   `json:"lbrBinaryModTimes"`
		LbrBinaryCopies         int64   `json:"lbrBinaryCopies"`
		LbrCompressOpens        int64   `json:"lbrCompressOpens"`
		LbrCompressCloses       int64   `json:"lbrCompressCloses"`
		LbrCompressCheckins     int64   `json:"lbrCompressCheckins"`
		LbrCompressExists       int64   `json:"lbrCompressExists"`
		LbrCompressReads        int64   `json:"lbrCompressReads"`
		LbrCompressReadBytes    int64   `json:"lbrCompressReadBytes"`
		LbrCompressWrites       int64   `json:"lbrCompressWrites"`
		LbrCompressWriteBytes   int64   `json:"lbrCompressWriteBytes"`
		LbrCompressDigests      int64   `json:"lbrCompressDigests"`
		LbrCompressFileSizes    int64   `json:"lbrCompressFileSizes"`
		LbrCompressModTimes     int64   `json:"lbrCompressModTimes"`
		LbrCompressCopies       int64   `json:"lbrCompressCopies"`
		LbrUncompressOpens      int64   `json:"lbrUncompressOpens"`
		LbrUncompressCloses     int64   `json:"lbrUncompressCloses"`
		LbrUncompressCheckins   int64   `json:"lbrUncompressCheckins"`
		LbrUncompressExists     int64   `json:"lbrUncompressExists"`
		LbrUncompressReads      int64   `json:"lbrUncompressReads"`
		LbrUncompressReadBytes  int64   `json:"lbrUncompressReadBytes"`
		LbrUncompressWrites     int64   `json:"lbrUncompressWrites"`
		LbrUncompressWriteBytes int64   `json:"lbrUncompressWriteBytes"`
		LbrUncompressDigests    int64   `json:"lbrUncompressDigests"`
		LbrUncompressFileSizes  int64   `json:"lbrUncompressFileSizes"`
		LbrUncompressModTimes   int64   `json:"lbrUncompressModTimes"`
		LbrUncompressCopies     int64   `json:"lbrUncompressCopies"`
		CmdError                bool    `json:"cmdError"`
		Tables                  []Table `json:"tables"`
	}{
		ProcessKey:              c.GetKey(),
		Cmd:                     c.Cmd,
		Pid:                     c.Pid,
		LineNo:                  c.LineNo,
		User:                    c.User,
		Workspace:               c.Workspace,
		ComputeLapse:            c.ComputeLapse,
		CompletedLapse:          c.CompletedLapse,
		Paused:                  c.Paused,
		IP:                      c.IP,
		App:                     c.App,
		Args:                    c.Args,
		StartTime:               c.StartTime.Format(p4timeformat),
		EndTime:                 c.EndTime.Format(p4timeformat),
		Running:                 c.Running,
		UCpu:                    c.UCpu,
		SCpu:                    c.SCpu,
		DiskIn:                  c.DiskIn,
		DiskOut:                 c.DiskOut,
		IpcIn:                   c.IpcIn,
		IpcOut:                  c.IpcOut,
		MaxRss:                  c.MaxRss,
		PageFaults:              c.PageFaults,
		MemMB:                   c.MemMB,
		MemPeakMB:               c.MemPeakMB,
		RPCMsgsIn:               c.RPCMsgsIn,
		RPCMsgsOut:              c.RPCMsgsOut,
		RPCSizeIn:               c.RPCSizeIn,
		RPCSizeOut:              c.RPCSizeOut,
		RPCHimarkFwd:            c.RPCHimarkFwd,
		RPCHimarkRev:            c.RPCHimarkRev,
		RPCSnd:                  c.RPCSnd,
		RPCRcv:                  c.RPCRcv,
		FileTotalsSnd:           c.FileTotalsSnd,
		FileTotalsRcv:           c.FileTotalsRcv,
		FileTotalsSndMBytes:     c.FileTotalsSndMBytes,
		FileTotalsRcvMBytes:     c.FileTotalsRcvMBytes,
		NetFilesAdded:           c.NetFilesAdded,
		NetFilesUpdated:         c.NetFilesUpdated,
		NetFilesDeleted:         c.NetFilesDeleted,
		NetBytesAdded:           c.NetBytesAdded,
		NetBytesUpdated:         c.NetBytesUpdated,
		LbrRcsOpens:             c.LbrRcsOpens,
		LbrRcsCloses:            c.LbrRcsCloses,
		LbrRcsCheckins:          c.LbrRcsCheckins,
		LbrRcsExists:            c.LbrRcsExists,
		LbrRcsReads:             c.LbrRcsReads,
		LbrRcsReadBytes:         c.LbrRcsReadBytes,
		LbrRcsWrites:            c.LbrRcsWrites,
		LbrRcsWriteBytes:        c.LbrRcsWriteBytes,
		LbrRcsDigests:           c.LbrRcsDigests,
		LbrRcsFileSizes:         c.LbrRcsFileSizes,
		LbrRcsModTimes:          c.LbrRcsModTimes,
		LbrRcsCopies:            c.LbrRcsCopies,
		LbrBinaryOpens:          c.LbrBinaryOpens,
		LbrBinaryCloses:         c.LbrBinaryCloses,
		LbrBinaryCheckins:       c.LbrBinaryCheckins,
		LbrBinaryExists:         c.LbrBinaryExists,
		LbrBinaryReads:          c.LbrBinaryReads,
		LbrBinaryReadBytes:      c.LbrBinaryReadBytes,
		LbrBinaryWrites:         c.LbrBinaryWrites,
		LbrBinaryWriteBytes:     c.LbrBinaryWriteBytes,
		LbrBinaryDigests:        c.LbrBinaryDigests,
		LbrBinaryModTimes:       c.LbrBinaryModTimes,
		LbrBinaryFileSizes:      c.LbrBinaryFileSizes,
		LbrBinaryCopies:         c.LbrBinaryCopies,
		LbrCompressOpens:        c.LbrCompressOpens,
		LbrCompressCloses:       c.LbrCompressCloses,
		LbrCompressCheckins:     c.LbrCompressCheckins,
		LbrCompressExists:       c.LbrCompressExists,
		LbrCompressReads:        c.LbrCompressReads,
		LbrCompressReadBytes:    c.LbrCompressReadBytes,
		LbrCompressWrites:       c.LbrCompressWrites,
		LbrCompressWriteBytes:   c.LbrCompressWriteBytes,
		LbrCompressDigests:      c.LbrCompressDigests,
		LbrCompressFileSizes:    c.LbrCompressFileSizes,
		LbrCompressModTimes:     c.LbrCompressModTimes,
		LbrCompressCopies:       c.LbrCompressCopies,
		LbrUncompressOpens:      c.LbrUncompressOpens,
		LbrUncompressCloses:     c.LbrUncompressCloses,
		LbrUncompressCheckins:   c.LbrUncompressCheckins,
		LbrUncompressExists:     c.LbrUncompressExists,
		LbrUncompressReads:      c.LbrUncompressReads,
		LbrUncompressReadBytes:  c.LbrUncompressReadBytes,
		LbrUncompressWrites:     c.LbrUncompressWrites,
		LbrUncompressWriteBytes: c.LbrUncompressWriteBytes,
		LbrUncompressDigests:    c.LbrUncompressDigests,
		LbrUncompressFileSizes:  c.LbrUncompressFileSizes,
		LbrUncompressModTimes:   c.LbrUncompressModTimes,
		LbrUncompressCopies:     c.LbrUncompressCopies,
		CmdError:                c.CmdError,
		Tables:                  tables,
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
	if other.Paused > 0 {
		c.Paused = other.Paused
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
	if other.MemMB > 0 {
		c.MemMB = other.MemMB
	}
	if other.MemPeakMB > 0 {
		c.MemPeakMB = other.MemPeakMB
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
	if other.FileTotalsSnd > 0 {
		c.FileTotalsSnd = other.FileTotalsSnd
	}
	if other.FileTotalsRcv > 0 {
		c.FileTotalsRcv = other.FileTotalsRcv
	}
	if other.FileTotalsSndMBytes > 0 {
		c.FileTotalsSndMBytes = other.FileTotalsSndMBytes
	}
	if other.FileTotalsRcvMBytes > 0 {
		c.FileTotalsRcvMBytes = other.FileTotalsRcvMBytes
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
	if other.CmdError {
		c.CmdError = other.CmdError
	}
	if len(other.Tables) > 0 {
		for k, t := range other.Tables {
			c.Tables[k] = t
		}
	}
	if other.LbrRcsOpens > 0 {
		c.LbrRcsOpens = other.LbrRcsOpens
	}
	if other.LbrRcsCloses > 0 {
		c.LbrRcsCloses = other.LbrRcsCloses
	}
	if other.LbrRcsCheckins > 0 {
		c.LbrRcsCheckins = other.LbrRcsCheckins
	}
	if other.LbrRcsExists > 0 {
		c.LbrRcsExists = other.LbrRcsExists
	}
	if other.LbrRcsReads > 0 {
		c.LbrRcsReads = other.LbrRcsReads
	}
	if other.LbrRcsReadBytes > 0 {
		c.LbrRcsReadBytes = other.LbrRcsReadBytes
	}
	if other.LbrRcsWrites > 0 {
		c.LbrRcsWrites = other.LbrRcsWrites
	}
	if other.LbrRcsWriteBytes > 0 {
		c.LbrRcsWriteBytes = other.LbrRcsWriteBytes
	}
	if other.LbrRcsDigests > 0 {
		c.LbrRcsDigests = other.LbrRcsDigests
	}
	if other.LbrRcsFileSizes > 0 {
		c.LbrRcsFileSizes = other.LbrRcsFileSizes
	}
	if other.LbrRcsModTimes > 0 {
		c.LbrRcsModTimes = other.LbrRcsModTimes
	}
	if other.LbrRcsCopies > 0 {
		c.LbrRcsCopies = other.LbrRcsCopies
	}
	if other.LbrBinaryOpens > 0 {
		c.LbrBinaryOpens = other.LbrBinaryOpens
	}
	if other.LbrBinaryCloses > 0 {
		c.LbrBinaryCloses = other.LbrBinaryCloses
	}
	if other.LbrBinaryCheckins > 0 {
		c.LbrBinaryCheckins = other.LbrBinaryCheckins
	}
	if other.LbrBinaryExists > 0 {
		c.LbrBinaryExists = other.LbrBinaryExists
	}
	if other.LbrBinaryReads > 0 {
		c.LbrBinaryReads = other.LbrBinaryReads
	}
	if other.LbrBinaryReadBytes > 0 {
		c.LbrBinaryReadBytes = other.LbrBinaryReadBytes
	}
	if other.LbrBinaryWrites > 0 {
		c.LbrBinaryWrites = other.LbrBinaryWrites
	}
	if other.LbrBinaryWriteBytes > 0 {
		c.LbrBinaryWriteBytes = other.LbrBinaryWriteBytes
	}
	if other.LbrBinaryDigests > 0 {
		c.LbrBinaryDigests = other.LbrBinaryDigests
	}
	if other.LbrBinaryFileSizes > 0 {
		c.LbrBinaryFileSizes = other.LbrBinaryFileSizes
	}
	if other.LbrBinaryModTimes > 0 {
		c.LbrBinaryModTimes = other.LbrBinaryModTimes
	}
	if other.LbrBinaryCopies > 0 {
		c.LbrBinaryCopies = other.LbrBinaryCopies
	}
	if other.LbrCompressOpens > 0 {
		c.LbrCompressOpens = other.LbrCompressOpens
	}
	if other.LbrCompressCloses > 0 {
		c.LbrCompressCloses = other.LbrCompressCloses
	}
	if other.LbrCompressCheckins > 0 {
		c.LbrCompressCheckins = other.LbrCompressCheckins
	}
	if other.LbrCompressExists > 0 {
		c.LbrCompressExists = other.LbrCompressExists
	}
	if other.LbrCompressReads > 0 {
		c.LbrCompressReads = other.LbrCompressReads
	}
	if other.LbrCompressReadBytes > 0 {
		c.LbrCompressReadBytes = other.LbrCompressReadBytes
	}
	if other.LbrCompressWrites > 0 {
		c.LbrCompressWrites = other.LbrCompressWrites
	}
	if other.LbrCompressWriteBytes > 0 {
		c.LbrCompressWriteBytes = other.LbrCompressWriteBytes
	}
	if other.LbrCompressDigests > 0 {
		c.LbrCompressDigests = other.LbrCompressDigests
	}
	if other.LbrCompressFileSizes > 0 {
		c.LbrCompressFileSizes = other.LbrCompressFileSizes
	}
	if other.LbrCompressModTimes > 0 {
		c.LbrCompressModTimes = other.LbrCompressModTimes
	}
	if other.LbrCompressCopies > 0 {
		c.LbrCompressCopies = other.LbrCompressCopies
	}
	if other.LbrUncompressOpens > 0 {
		c.LbrUncompressOpens = other.LbrUncompressOpens
	}
	if other.LbrUncompressCloses > 0 {
		c.LbrUncompressCloses = other.LbrUncompressCloses
	}
	if other.LbrUncompressCheckins > 0 {
		c.LbrUncompressCheckins = other.LbrUncompressCheckins
	}
	if other.LbrUncompressExists > 0 {
		c.LbrUncompressExists = other.LbrUncompressExists
	}
	if other.LbrUncompressReads > 0 {
		c.LbrUncompressReads = other.LbrUncompressReads
	}
	if other.LbrUncompressReadBytes > 0 {
		c.LbrUncompressReadBytes = other.LbrUncompressReadBytes
	}
	if other.LbrUncompressWrites > 0 {
		c.LbrUncompressWrites = other.LbrUncompressWrites
	}
	if other.LbrUncompressWriteBytes > 0 {
		c.LbrUncompressWriteBytes = other.LbrUncompressWriteBytes
	}
	if other.LbrUncompressDigests > 0 {
		c.LbrUncompressDigests = other.LbrUncompressDigests
	}
	if other.LbrUncompressFileSizes > 0 {
		c.LbrUncompressFileSizes = other.LbrUncompressFileSizes
	}
	if other.LbrUncompressModTimes > 0 {
		c.LbrUncompressModTimes = other.LbrUncompressModTimes
	}
	if other.LbrUncompressCopies > 0 {
		c.LbrUncompressCopies = other.LbrUncompressCopies
	}
}

// P4dFileParser - manages state
type P4dFileParser struct {
	logger               *logrus.Logger
	outputDuration       time.Duration
	debugDuration        time.Duration
	cmdsMaxResetDuration time.Duration // Window after which CmdsRunningMax/CmdsPausedMax are reset
	lineNo               int64
	m                    sync.Mutex
	cmds                 map[int64]*Command
	CmdsCount            int //Count of commands processed
	ServerEventsCount    int // Count of server event records processed
	cmdChan              chan interface{}
	timeChan             chan time.Time
	linesChan            *<-chan string
	blockChan            chan *Block
	currTime             time.Time
	debug                int
	noCompletionRecords  bool // Can be set if completion records not expected - e.g. configurable server=1
	currStartTime        time.Time
	timeLastCmdProcessed time.Time
	timeLastSvrEvent     time.Time
	pidsSeenThisSecond   map[int64]bool
	cmdsRunning          int64           // No of currently running threads
	cmdsRunningMax       int64           // Max No of currently running threads
	cmdsPaused           int64           // No of paused threads
	cmdsPausedMax        int64           // Max no of paused threads
	cmdsPausedErrorCount int64           // Count of commands paused due to resource pressure errors
	pauseRateCPU         int64           // Resource pressure
	pauseRateMem         int64           // ditto
	cpuPressureState     int64           // ditto
	memPressureState     int64           // ditto
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
	fp.cmdsMaxResetDuration = time.Second * 10
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

// SetNoCompletionRecords - don't expect completion records
func (fp *P4dFileParser) SetNoCompletionRecords() {
	fp.noCompletionRecords = true
}

func (fp *P4dFileParser) debugLog(cmd *Command) bool {
	return cmd != nil && cmd.Pid == fp.debugPID && cmd.Cmd == fp.debugCmd
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
			fp.cmdsRunning++
			cmd.Running = fp.cmdsRunning
			cmd.countedInRunning = true
		}
	} else {
		if cmd.countedInRunning {
			recorded = true
			fp.cmdsRunning--
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
		fp.logger.Debugf("running: %d delta %d recorded %v %s cmd %s pid %d line %d", fp.cmdsRunning, delta, recorded, msg, cmd.Cmd, cmd.Pid, cmd.LineNo)
	}
}

func (fp *P4dFileParser) addCommand(newCmd *Command, hasTrackInfo bool) {
	debugLog := fp.debugLog(newCmd) || FlagSet(fp.debug, DebugAddCommands)
	if debugLog {
		fp.logger.Infof("addCommand: start: pid %d, hasTrack %v, lineNo %d, cmd %s, dup %v", newCmd.Pid, hasTrackInfo, newCmd.LineNo, newCmd.Cmd, newCmd.duplicateKey)
	}
	if fp.currTime.IsZero() || newCmd.StartTime.After(fp.currTime) {
		fp.currTime = newCmd.StartTime
		if debugLog {
			fp.logger.Infof("addCommand: currTime %v", fp.currTime)
		}
	}
	newCmd.Running = fp.cmdsRunning
	if fp.currStartTime != newCmd.StartTime && newCmd.StartTime.After(fp.currStartTime) {
		fp.currStartTime = newCmd.StartTime
		fp.pidsSeenThisSecond = make(map[int64]bool)
	}
	if cmd, ok := fp.cmds[newCmd.Pid]; ok {
		if debugLog {
			fp.logger.Infof("addCommand: found same pid %d lineNo %d cmd %s dup %v", cmd.Pid, cmd.LineNo, cmd.Cmd, cmd.duplicateKey)
		}
		if cmd.ProcessKey != "" && cmd.ProcessKey != newCmd.ProcessKey {
			if hasTrackInfo && !cmdHasRealTableTrackInfo(newCmd) {
				if debugLog {
					fp.logger.Infof("addCommand: ignoring dummy track for pid %d", cmd.Pid)
				}
			} else {
				if debugLog {
					fp.logger.Infof("addCommand: outputting old since process key different pid %d", cmd.Pid)
				}
				fp.outputCmd(cmd)
				fp.cmds[newCmd.Pid] = newCmd // Replace previous cmd with same PID
				if !cmdHasNoCompletionRecord(newCmd) {
					fp.trackRunning("t01", newCmd, 1)
				}
			}
		} else if cmdHasNoCompletionRecord(newCmd) {
			// Even if they have track info, we output the old command
			if debugLog {
				fp.logger.Infof("addCommand: outputting old since no trackInfo pid %d", cmd.Pid)
			}
			fp.outputCmd(cmd)
			newCmd.duplicateKey = true
			fp.cmds[newCmd.Pid] = newCmd // Replace previous cmd with same PID
		} else {
			// Typically track info only present when command has completed - especially for duplicates
			// Interactive pull commands are an exception - they may have track records for rdb.lbr and then a final set too.
			// Syncs etc also set intermediate track info
			if cmd.hasTrackInfo && cmdHasRealTableTrackInfo(newCmd) {
				if cmd.LineNo == newCmd.LineNo || (cmd.Cmd == "user-pull" && !cmdPullAutomatic(cmd.Args)) {
					if debugLog {
						fp.logger.Infof("addCommand: updating duplicate pid %d", cmd.Pid)
					}
					cmd.updateFrom(newCmd)
				} else {
					if debugLog {
						fp.logger.Infof("addCommand: found duplicate - outputting old pid %d", cmd.Pid)
					}
					fp.outputCmd(cmd)
					fp.trackRunning("t02", newCmd, 1)
					newCmd.duplicateKey = true
					fp.cmds[newCmd.Pid] = newCmd // Replace previous cmd with same PID
				}
			} else {
				if debugLog {
					fp.logger.Infof("addCommand: updating pid %d", cmd.Pid)
				}
				cmd.updateFrom(newCmd)
			}
		}
		if hasTrackInfo {
			if debugLog {
				fp.logger.Infof("addCommand: setting hasTrackInfo=true pid %d", cmd.Pid)
			}
			cmd.hasTrackInfo = true
		}
	} else {
		if debugLog {
			fp.logger.Infof("addCommand: remembering newCmd pid %d", newCmd.Pid)
		}
		fp.cmds[newCmd.Pid] = newCmd
		if _, ok := fp.pidsSeenThisSecond[newCmd.Pid]; ok {
			if !cmdHasRealTableTrackInfo(newCmd) { // Ignore commands which update clientEntity locks for example
				if debugLog {
					fp.logger.Infof("addCommand: setting duplicate pid %d", newCmd.Pid)
				}
				newCmd.duplicateKey = true
			}
		}
		fp.pidsSeenThisSecond[newCmd.Pid] = true
		if !cmdHasNoCompletionRecord(newCmd) && !newCmd.completed {
			fp.trackRunning("t03", newCmd, 1)
		}
	}
	fp.outputCompletedCommands()
}

// Commands are treated as having no track info if they have no table entries, or the only
// tables are things like rdb.lbr
func cmdHasRealTableTrackInfo(cmd *Command) bool {
	if len(cmd.Tables) == 0 {
		return false
	}
	if _, ok := cmd.Tables["rdb.lbr"]; ok { // If only table is this one ignore it as can be update multiple times
		return len(cmd.Tables) > 1
	}
	return true
}

// Special commands which only have start records not completion records
// This was a thing with older p4d versions but now all commands have them
// Note that pull status commands (not automatic background pull threads) have completion records
func cmdHasNoCompletionRecord(cmd *Command) bool {
	return cmd.Cmd == "rmt-FileFetch" ||
		cmd.Cmd == "rmt-FileFetchMulti" ||
		// cmdName == "rmt-Journal" ||
		cmd.Cmd == "rmt-JournalPos" ||
		cmd.Cmd == "client-Stats" ||
		cmd.Cmd == "pull" && cmdPullAutomatic(cmd.Args)
}

var rePullAutoArgs = regexp.MustCompile(`\-(\w*)[iI]`) // Auto pull commands have an interactive -i arg

// Whether pull has background args
func cmdPullAutomatic(args string) bool {
	return rePullAutoArgs.MatchString(args)
}

var trackStart = "---"
var trackLapse = "--- lapse "
var trackPaused = "--- paused "
var trackFatalError = "--- exited on fatal server error"
var trackDB = "--- db."
var trackRdbLbr = "--- rdb.lbr"
var trackMeta = "--- meta"
var trackClients = "--- clients"
var trackChange = "--- change"
var trackClientEntity = "--- clientEntity"
var trackReplicaPull = "--- replica/pull"
var trackStorage = "--- storageup/"
var trackLbrRcs = "--- lbr Rcs"
var trackLbrBinary = "--- lbr Binary"
var trackLbrCompress = "--- lbr Compress"
var trackLbrUncompress = "--- lbr Uncompress"
var reCmdTrigger = regexp.MustCompile(` trigger ([^ ]+)$`)
var reTriggerLapse = regexp.MustCompile(`^lapse (\d+\.\d+)s|^lapse (\.\d+)s|^lapse (\d+)s`)
var prefixTrackCmdMem = "--- memory cmd/proc "
var prefixTrackRPC = "--- rpc msgs/size in+out "
var prefixTrackFileTotals = "--- filetotals (svr) send/recv files+bytes "
var prefixTrackFileTotalsClient = "--- filetotals (client) send/recv files+bytes "
var prefixTrackLbr = "---   opens+closes"
var prefixTrackLbr2 = "---   reads+readbytes"
var prefixTrackLbr3 = "---   digests+filesizes"
var reTrackLbr = regexp.MustCompile(`^---   opens\+closes\+checkins\+exists +(\d+)\+(\d+)\+(\d+)\+(\d+)`)
var reTrackLbrReadWrite = regexp.MustCompile(`^---   reads\+readbytes\+writes\+writebytes (\d+)\+([\.0-9KMGTP]+)\+(\d+)\+([\.0-9KMGTP]+)`)
var reTrackLbrDigestFilesize = regexp.MustCompile(`^---   digests\+filesizes\+modtimes\+copies +(\d+)\+(\d+)\+(\d+)\+(\d+)`)
var reTrackCmdMem = regexp.MustCompile(`^--- memory cmd/proc (\d+)mb\/(\d+)mb`)
var reTrackRPC = regexp.MustCompile(`^--- rpc msgs/size in\+out (\d+)\+(\d+)/(\d+)mb\+(\d+)mb himarks (\d+)/(\d+)`)
var reTrackRPC2 = regexp.MustCompile(`^--- rpc msgs/size in\+out (\d+)\+(\d+)/(\d+)mb\+(\d+)mb himarks (\d+)/(\d+) snd/rcv ([0-9]+|[0-9]+\.[0-9]+|\.[0-9]+)s/([0-9]+|[0-9]+\.[0-9]+|\.[0-9]+)s`)
var reTrackFileTotals = regexp.MustCompile(`^--- filetotals \(svr\) send/recv files\+bytes (\d+)\+(\d+)mb/(\d+)\+(\d+)mb`)
var reTrackFileTotalsClient = regexp.MustCompile(`^--- filetotals \(client\) send/recv files\+bytes (\d+)\+(\d+)mb/(\d+)\+(\d+)mb`)
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
	var lbrAction string
	for _, line := range lines {
		if strings.HasPrefix(line, trackLapse) {
			val := line[len(trackLapse):]
			j := strings.Index(val, "s")
			if j > 0 {
				f, _ := strconv.ParseFloat(string(val[:j]), 32)
				cmd.CompletedLapse = float32(f)
			}
			hasTrackInfo = true
			continue
		}
		if strings.HasPrefix(line, trackPaused) {
			val := line[len(trackPaused):]
			j := strings.Index(val, "s")
			if j > 0 {
				f, _ := strconv.ParseFloat(string(val[:j]), 32)
				cmd.Paused = float32(f)
			}
			if fp.cmdsPaused > 0 {
				fp.cmdsPaused -= 1 // Decrement count (may be reset by a future paused block - but those are not always reliable)
			}
			hasTrackInfo = true
			continue
		}
		if strings.HasPrefix(line, trackFatalError) {
			cmd.CmdError = true
			hasTrackInfo = true
			fp.cmdsPausedErrorCount += 1
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
		if strings.HasPrefix(line, prefixTrackCmdMem) {
			m = reTrackCmdMem.FindStringSubmatch(line)
			if len(m) > 0 {
				cmd.setMem(m[1], m[2])
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
		if strings.HasPrefix(line, prefixTrackFileTotals) {
			m = reTrackFileTotals.FindStringSubmatch(line)
			if len(m) > 0 {
				cmd.setFileTotals(m[1], m[2], m[3], m[4])
				hasTrackInfo = true
				continue
			}
		}
		if strings.HasPrefix(line, prefixTrackFileTotalsClient) {
			m = reTrackFileTotalsClient.FindStringSubmatch(line)
			if len(m) > 0 {
				cmd.setFileTotals(m[1], m[2], m[3], m[4])
				hasTrackInfo = true
				continue
			}
		}
		if strings.HasPrefix(line, trackLbrRcs) {
			lbrAction = "lbrRcs"
			hasTrackInfo = true
			continue
		}
		if strings.HasPrefix(line, trackLbrBinary) {
			lbrAction = "lbrBinary"
			hasTrackInfo = true
			continue
		}
		if strings.HasPrefix(line, trackLbrCompress) {
			lbrAction = "lbrCompress"
			hasTrackInfo = true
			continue
		}
		if strings.HasPrefix(line, trackLbrUncompress) {
			lbrAction = "lbrUncompress"
			hasTrackInfo = true
			continue
		}
		// Process lbr records if we found some
		if lbrAction == "lbrRcs" {
			m = reTrackLbr.FindStringSubmatch(line)
			if len(m) > 0 {
				if strings.HasPrefix(line, prefixTrackLbr) {
					cmd.setLbrRcsOpensCloses(m[1], m[2], m[3], m[4])
					continue
				}
			}
			m = reTrackLbrReadWrite.FindStringSubmatch(line)
			if len(m) > 0 {
				if strings.HasPrefix(line, prefixTrackLbr2) {
					cmd.setLbrRcsReadWrites(m[1], m[3], parseBytesString(m[2]), parseBytesString(m[4]))
					continue
				}
			}
			m = reTrackLbrDigestFilesize.FindStringSubmatch(line)
			if len(m) > 0 {
				if strings.HasPrefix(line, prefixTrackLbr3) {
					cmd.setLbrRcsDigestFilesizes(m[1], m[2], m[3], m[4])
					continue
				}
			}
		}
		if lbrAction == "lbrBinary" {
			m = reTrackLbr.FindStringSubmatch(line)
			if len(m) > 0 {
				if strings.HasPrefix(line, prefixTrackLbr) {
					cmd.setLbrBinaryOpensCloses(m[1], m[2], m[3], m[4])
					continue
				}
			}
			m = reTrackLbrReadWrite.FindStringSubmatch(line)
			if len(m) > 0 {
				if strings.HasPrefix(line, prefixTrackLbr2) {
					cmd.setLbrBinaryReadWrites(m[1], m[3], parseBytesString(m[2]), parseBytesString(m[4]))
					continue
				}
			}
			m = reTrackLbrDigestFilesize.FindStringSubmatch(line)
			if len(m) > 0 {
				if strings.HasPrefix(line, prefixTrackLbr3) {
					cmd.setLbrBinaryDigestFilesizes(m[1], m[2], m[3], m[4])
					continue
				}
			}
		}
		if lbrAction == "lbrCompress" {
			m = reTrackLbr.FindStringSubmatch(line)
			if len(m) > 0 {
				if strings.HasPrefix(line, prefixTrackLbr) {
					cmd.setLbrCompressOpensCloses(m[1], m[2], m[3], m[4])
					continue
				}
			}
			m = reTrackLbrReadWrite.FindStringSubmatch(line)
			if len(m) > 0 {
				if strings.HasPrefix(line, prefixTrackLbr2) {
					cmd.setLbrCompressReadWrites(m[1], m[3], parseBytesString(m[2]), parseBytesString(m[4]))
					continue
				}
			}
			m = reTrackLbrDigestFilesize.FindStringSubmatch(line)
			if len(m) > 0 {
				if strings.HasPrefix(line, prefixTrackLbr3) {
					cmd.setLbrCompressDigestFilesizes(m[1], m[2], m[3], m[4])
					continue
				}
			}
		}
		if lbrAction == "lbrUncompress" {
			m = reTrackLbr.FindStringSubmatch(line)
			if len(m) > 0 {
				if strings.HasPrefix(line, prefixTrackLbr) {
					cmd.setLbrUncompressOpensCloses(m[1], m[2], m[3], m[4])
					continue
				}
			}
			m = reTrackLbrReadWrite.FindStringSubmatch(line)
			if len(m) > 0 {
				if strings.HasPrefix(line, prefixTrackLbr2) {
					cmd.setLbrUncompressReadWrites(m[1], m[3], parseBytesString(m[2]), parseBytesString(m[4]))
					continue
				}
			}
			m = reTrackLbrDigestFilesize.FindStringSubmatch(line)
			if len(m) > 0 {
				if strings.HasPrefix(line, prefixTrackLbr3) {
					cmd.setLbrUncompressDigestFilesizes(m[1], m[2], m[3], m[4])
					continue
				}
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
				buf := fmt.Sprintf("Unrecognised track table: %d %s\n", cmd.LineNo, line)
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
			buf := fmt.Sprintf("Unrecognised track: %d %s\n", cmd.LineNo, string(line))
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

// Extract values from strings such as "1.1K" or "2.3G"
func parseBytesString(value string) int64 {
	l := value[len(value)-1:]
	s, _ := strconv.ParseFloat(value[:len(value)-1], 32)
	var rtnVal int64
	if l == "K" {
		rtnVal = int64(s * 1024)
	} else if l == "M" {
		rtnVal = int64(s * 1024 * 1024)
	} else if l == "G" {
		rtnVal = int64(s * 1024 * 1024 * 1024)
	} else if l == "T" {
		rtnVal = int64(s * 1024 * 1024 * 1024 * 1024)
	} else if l == "P" {
		rtnVal = int64(s * 1024 * 1024 * 1024 * 1024 * 1024)
	} else {
		f, _ := strconv.ParseFloat(value, 32)
		rtnVal = int64(f)
	}
	return rtnVal
}

// Output a single command to appropriate channel
func (fp *P4dFileParser) outputCmd(cmd *Command) {
	fp.trackRunning("t04", cmd, -1)
	if fp.debugLog(cmd) {
		fp.logger.Infof("outputCmd: pid %d lineNo %d cmd %s dup %v", cmd.Pid, cmd.LineNo, cmd.Cmd, cmd.duplicateKey)
	}
	cmd.updateStartEndTimes() // Required in some cases with partial records
	if FlagSet(fp.debug, DebugAddCommands) && fp.timeLastCmdProcessed != fp.currTime {
		fp.logger.Debugf("outputCmd: updating tlcp from %v to %v", fp.timeLastCmdProcessed, fp.currTime)
	}
	if fp.currTime.Sub(fp.timeLastCmdProcessed) > 0 {
		fp.timeLastCmdProcessed = fp.currTime
	}
	// Ensure entire structure is copied, particularly map member to avoid concurrency issues
	cmdcopy := *cmd
	if cmdHasNoCompletionRecord(cmd) {
		cmdcopy.EndTime = cmdcopy.StartTime
	}
	cmdcopy.Tables = make(map[string]*Table, len(cmd.Tables))
	i := 0
	for k, v := range cmd.Tables {
		cmdcopy.Tables[k] = v
		i++
	}
	if fp.debugLog(&cmdcopy) {
		fp.logger.Infof("outputCmd: computelapse %v completelapse %v endTime %s", cmdcopy.ComputeLapse,
			cmdcopy.CompletedLapse, cmdcopy.EndTime)
	}
	fp.cmdChan <- cmdcopy
	fp.CmdsCount++
}

// Output a server event to appropriate channel
func (fp *P4dFileParser) outputSvrEvent(timeStr string, lineNo int64) {
	eventTime, _ := time.Parse(p4timeformat, timeStr)
	// Record the values when we last output a server event - means we can update if things change.
	if FlagSet(fp.debug, DebugTrackPaused) {
		fp.logger.Debugf("paused: line %d running/max: %d/%d paused/max %d/%d window %.2f s",
			lineNo, fp.cmdsRunning, fp.cmdsRunningMax, fp.cmdsPaused, fp.cmdsPausedMax, fp.currTime.Sub(fp.timeLastSvrEvent).Seconds())
	}
	if fp.cmdsPaused > fp.cmdsPausedMax {
		fp.cmdsPausedMax = fp.cmdsPaused
	}
	if fp.cmdsRunning > fp.cmdsRunningMax {
		fp.cmdsRunningMax = fp.cmdsRunning
	}
	if fp.currTime.Sub(fp.timeLastSvrEvent) > fp.cmdsMaxResetDuration {
		fp.cmdsPausedMax = fp.cmdsPaused
		fp.cmdsRunningMax = fp.cmdsRunning
		fp.timeLastSvrEvent = fp.currTime
	}
	svrEvent := ServerEvent{
		EventTime:        eventTime,
		LineNo:           lineNo,
		ActiveThreads:    fp.cmdsRunning,
		ActiveThreadsMax: fp.cmdsRunningMax,
		PausedThreads:    fp.cmdsPaused,
		PausedThreadsMax: fp.cmdsPausedMax,
		PausedErrorCount: fp.cmdsPausedErrorCount,
		PauseRateCPU:     fp.pauseRateCPU,
		PauseRateMem:     fp.pauseRateMem,
		CPUPressureState: fp.cpuPressureState,
		MemPressureState: fp.memPressureState,
	}
	fp.cmdChan <- svrEvent
	fp.ServerEventsCount++
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
					fp.logger.Infof("outputCompletedCmds: r1 pid %d lineNo %d cmd %s", cmd.Pid, cmd.LineNo, cmd.Cmd)
				}
				completed = true
			} else if !cmd.EndTime.IsZero() && fp.currStartTime.Sub(cmd.EndTime) >= timeWindow {
				if debugLog {
					fp.logger.Infof("outputCompletedCmds: r2 pid %d lineNo %d cmd %s", cmd.Pid, cmd.LineNo, cmd.Cmd)
				}
				completed = true
			} else if !fp.timeLastCmdProcessed.IsZero() && fp.currTime.Sub(fp.timeLastCmdProcessed) >= timeWindow {
				if debugLog {
					fp.logger.Infof("outputCompletedCmds: r3 pid %d lineNo %d cmd %s currT %s tlcp %s", cmd.Pid, cmd.LineNo, cmd.Cmd, fp.currTime, fp.timeLastCmdProcessed)
				}
				completed = true
			}
		}
		// We have observed logs with very few "completed" records.
		if !completed && (cmd.hasTrackInfo && cmd.computeEndTime() != blankTime &&
			fp.currStartTime.Sub(cmd.computeEndTime()) >= timeWindow) {
			if debugLog {
				fp.logger.Infof("outputCompletedCmds: r4 pid %d lineNo %d cmd %s", cmd.Pid, cmd.LineNo, cmd.Cmd)
			}
			completed = true
		}
		// Handle the special commands which don't receive a completed time - we use StartTime
		if debugLog {
			fp.logger.Infof("outputCompletedCmds: r4a pid %d lineNo %d cmd %s start %v completed %v diff %v", cmd.Pid, cmd.LineNo, cmd.Cmd, cmd.StartTime, completed, fp.currStartTime.Sub(cmd.StartTime))
		}
		if !completed && fp.currStartTime.Sub(cmd.StartTime) >= timeWindow && (cmdHasNoCompletionRecord(cmd) || fp.noCompletionRecords) {
			if debugLog {
				fp.logger.Infof("outputCompletedCmds: r5 pid %d lineNo %d cmd %s", cmd.Pid, cmd.LineNo, cmd.Cmd)
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
		if FlagSet(fp.debug, DebugAddCommands) {
			fp.logger.Debugf("outputCompletedCmds: updating tlcp from %v to %v", fp.timeLastCmdProcessed, fp.currTime)
		}
		fp.timeLastCmdProcessed = fp.currTime
	}
	if fp.logger != nil && fp.debug > 0 {
		endCount := len(fp.cmds)
		fp.logger.Debugf("outputCompletedCmds: start %d, end %d, count %d, continued %d, exited %d",
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
		f, _ := strconv.ParseFloat(string(computeLapse), 32)
		cmd.ComputeLapse = float32(f)
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
		for a := 0; a < len(m)-1; a++ {
			if string(m[a+1]) != "" {
				s := fmt.Sprintf("0%s", string(m[a+1]))
				triggerLapse, _ = strconv.ParseFloat(s, 32)
				break
			}
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
			// Note multiline descriptions will not be appended to the cmd.Args value - just the first line
			m = reCmdMultiLineDesc.FindStringSubmatch(line)
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
			// Detect trigger entries
			trigger := ""
			if i := strings.Index(line, "' trigger "); i >= 0 {
				tm := reCmdTrigger.FindStringSubmatch(line[i:])
				if len(tm) > 0 {
					trigger = string(tm[1])
				}
				line = line[:i+1] // Strip from the line
			}
			// Detect slightly strange IDLE, Init() commands
			if i := strings.Index(line, "' exited unexpectedly, removed from monitor table."); i >= 0 {
				if fcmd, ok := fp.cmds[cmd.Pid]; ok {
					fcmd.CmdError = true
					fcmd.completed = true
					if fcmd.EndTime.IsZero() {
						fcmd.EndTime = fcmd.StartTime
					}
					if !cmdHasNoCompletionRecord(fcmd) {
						fp.trackRunning("t06", fcmd, -1)
					}
				}
				return
			}
			h := md5.Sum([]byte(line))
			cmd.ProcessKey = hex.EncodeToString(h[:])
			// if fp.debugLog(cmd) {
			// 	fp.logger.Debugf("Setting pid %d, processKey %s, '%s'", cmd.Pid, cmd.ProcessKey, line)
			// }
			if len(trigger) > 0 {
				fp.processTriggerLapse(cmd, trigger, block.lines[len(block.lines)-1])
			}
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
				buf := fmt.Sprintf("Unrecognised: %d %s\n", block.lineNo, line)
				if fp.logger != nil {
					fp.logger.Trace(buf)
				} else {
					fmt.Fprint(os.Stderr, buf)
				}
			}
		}
	}
	if cmd != nil {
		fp.addCommand(cmd, false) // Only happens if no track records - which will already have added the command
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
				// Use to be the case that errors would ensure nothing else for commands, but no longer!
				// cmd.completed = true
				if !cmdHasNoCompletionRecord(cmd) {
					fp.trackRunning("t06", cmd, -1)
				}
			}
			return
		}
	}
}

func (fp *P4dFileParser) processServerThreadsBlock(block *Block) {
	fp.hadServerThreadsMsg = true
	line := block.lines[0]
	m := reServerThreads.FindStringSubmatch(line)
	if len(m) > 0 {
		i, err := strconv.ParseInt(m[3], 10, 64)
		if err == nil {
			fp.cmdsRunning = i
			fp.logger.Debugf("Encountered server running threads (%d) message", i)
			fp.outputSvrEvent(m[1], block.lineNo)
		}
	}
}

func (fp *P4dFileParser) processPausedThreadsBlock(block *Block) {
	line := block.lines[0]
	m := rePausedThreads.FindStringSubmatch(line)
	if len(m) > 0 {
		i, err := strconv.ParseInt(m[3], 10, 64)
		if err == nil {
			fp.cmdsPaused = i
			fp.logger.Debugf("Encountered server paused threads (%d) message", i)
			fp.outputSvrEvent(m[1], block.lineNo)
		}
	}
}

func (fp *P4dFileParser) processResourcePressureBlock(block *Block) {
	fp.hadServerThreadsMsg = true
	line := block.lines[0]
	m := reResourcePressure.FindStringSubmatch(line)
	if len(m) > 0 {
		fp.logger.Debugf("Encountered server resource pressure message")
		fp.pauseRateCPU = toInt64(m[3])
		fp.pauseRateMem = toInt64(m[4])
		fp.cpuPressureState = toInt64(m[5])
		fp.memPressureState = toInt64(m[6])
		fp.outputSvrEvent(m[1], block.lineNo)
	}
}

func (fp *P4dFileParser) processBlock(block *Block) {
	if block.btype == infoType {
		fp.processInfoBlock(block)
	} else if block.btype == activeThreadsType {
		fp.processServerThreadsBlock(block)
	} else if block.btype == pausedThreadsType {
		fp.processPausedThreadsBlock(block)
	} else if block.btype == resourcePressureType {
		fp.processResourcePressureBlock(block)
	} else if block.btype == errorType {
		fp.processErrorBlock(block)
	} //TODO: output unrecognised block if wanted
}

func blankLine(line string) bool {
	return len(line) == 0
}

// Basic strings which start/end a block
var blockEnds = []string{
	"Perforce server info:",
	"Perforce server error:",
}

// Various line prefixes that both can end a block, and should be ignored - see ignoreLine
var BlockEndPrefixes = []string{
	"Rpc himark:",
	"server to client",
	"server to inter",
	"Forwarder set trusted client address",
	"NetSslTransport::SendOrReceive", // Optional configurable
}

// 2024/06/19 12:25:31 560465376 pid 1056102: Server is now using 55 active threads.
// 2024/06/19 12:25:31 560486548 pid 1056102: Server now has 10 paused threads.
// 2024/06/19 12:25:38 004246895 pid 1056103: Server under resource pressure.  Pause rate CPU 59%, mem 0%, CPU pressure 2, mem pressure 0

var msgActiveThreads = " active threads."
var msgPausedThreads = " paused threads."
var msgResourcePressure = " Server under resource pressure.  Pause rate CPU"
var reServerThreads = regexp.MustCompile(`^(\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d) \d+ pid (\d+): Server is now using (\d+) active threads.`)
var rePausedThreads = regexp.MustCompile(`^(\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d) \d+ pid (\d+): Server now has (\d+) paused threads.`)
var reResourcePressure = regexp.MustCompile(`^(\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d) \d+ pid (\d+): Server under resource pressure.  Pause rate CPU (\d+)%, mem (\d+)%, CPU pressure (\d+), mem pressure (\d+)`)

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
	if strings.HasSuffix(line, msgActiveThreads) { // OK to do a regex as does occur frequently
		if m := reServerThreads.FindStringSubmatch(line); len(m) > 0 {
			return true
		}
	}
	if strings.HasSuffix(line, msgPausedThreads) {
		if m := rePausedThreads.FindStringSubmatch(line); len(m) > 0 {
			return true
		}
	}
	if strings.Contains(line, msgResourcePressure) {
		if m := reResourcePressure.FindStringSubmatch(line); len(m) > 0 {
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

// CmdsPendingCount - count of unmatched commands
func (fp *P4dFileParser) CmdsPendingCount() int {
	fp.m.Lock()
	defer fp.m.Unlock()
	return len(fp.cmds)
}

// LogParser - interface to be run on a go routine - commands are returned on cmdchan
func (fp *P4dFileParser) LogParser(ctx context.Context, linesChan <-chan string, timeChan <-chan time.Time) chan interface{} {
	fp.lineNo = 1

	fp.cmdChan = make(chan interface{}, 10000)
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
				case t := <-ticker.C:
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
				fp.outputRemainingCommands()
				return
			case b, ok := <-fp.blockChan:
				if ok {
					fp.processBlock(b)
					if fp.cmdsRunning > maxRunningCount {
						panic(fmt.Sprintf("ERROR: max running command limit (%d) exceeded. Does this server log have completion records configured (p4 configure set server=3)? "+
							"If using log2sql, then you can try to re-run with parameter --no.completion.records - but we strongly recommend you change p4d configurable to get completion records instead and re-analyze the log!",
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
