package main

import (
	"bufio"
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	p4dlog "github.com/rcowham/go-libp4dlog"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var (
	eol = regexp.MustCompile("\r\n|\n")
)

func getResult(output chan string) []string {
	lines := []string{}
	for line := range output {
		lines = append(lines, line)
	}
	return lines
}

func parseLogLines(input string) []string {

	inchan := make(chan string, 10)

	logger := logrus.New()
	logger.Level = logrus.InfoLevel
	fp := p4dlog.NewP4dFileParser(logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmdChan := fp.LogParser(ctx, inchan, nil)

	scanner := bufio.NewScanner(strings.NewReader(input))
	for scanner.Scan() {
		inchan <- scanner.Text()
	}
	close(inchan)

	output := []string{}
	for cmd := range cmdChan {
		output = append(output, fmt.Sprintf("%s", cmd.String()))
	}
	sort.Strings(output)
	return output
}

func TestLogParse(t *testing.T) {
	testInput := `
Perforce server info:
	2015/09/02 15:23:09 pid 1616 robert@robert-test 127.0.0.1 [Microsoft Visual Studio 2013/12.0.21005.1] 'user-sync //...'
Perforce server info:
	2015/09/02 15:23:09 pid 1616 compute end .031s
Perforce server info:
	2015/09/02 15:23:09 pid 1616 completed .031s`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	//assert.Equal(t, "", output[0])
	assert.JSONEq(t, `{"processKey":"4d4e5096f7b732e4ce95230ef085bf51","cmd":"user-sync","pid":1616,"lineNo":2,"user":"robert","workspace":"robert-test","computeLapse":0.031,"completedLapse":0.031,"ip":"127.0.0.1","app":"Microsoft Visual Studio 2013/12.0.21005.1","args":"//...","startTime":"2015/09/02 15:23:09","endTime":"2015/09/02 15:23:09","running":1,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"netFilesAdded":0,"netFilesUpdated":0,"netFilesDeleted":0,"netBytesAdded":0,"netBytesUpdated":0,"lbrRcsOpens":0,"lbrRcsCloses":0,"lbrRcsCheckins":0,"lbrRcsExists":0,"lbrRcsReads":0,"lbrRcsReadBytes":0,"lbrRcsWrites":0,"lbrRcsWriteBytes":0,"lbrCompressOpens":0,"lbrCompressCloses":0,"lbrCompressCheckins":0,"lbrCompressExists":0,"lbrCompressReads":0,"lbrCompressReadBytes":0,"lbrCompressWrites":0,"lbrCompressWriteBytes":0,"lbrUncompressOpens":0,"lbrUncompressCloses":0,"lbrUncompressCheckins":0,"lbrUncompressExists":0,"lbrUncompressReads":0,"lbrUncompressReadBytes":0,"lbrUncompressWrites":0,"lbrUncompressWriteBytes":0,"cmdError":false,"tables":[]}`,
		output[0])

}

func TestSimpleRunning(t *testing.T) {
	// No completion record
	testInput := `
Perforce server info:
	2015/09/02 15:23:09 pid 1616 robert@robert-test 127.0.0.1 [Microsoft Visual Studio 2013/12.0.21005.1] 'user-sync //...'
Perforce server info:
	2015/09/02 15:23:09 pid 1616 compute end .031s`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	//assert.Equal(t, "", output[0])
	assert.JSONEq(t, `{"processKey":"4d4e5096f7b732e4ce95230ef085bf51","cmd":"user-sync","pid":1616,"lineNo":2,"user":"robert","workspace":"robert-test","computeLapse":0.031,"completedLapse":0,"ip":"127.0.0.1","app":"Microsoft Visual Studio 2013/12.0.21005.1","args":"//...","startTime":"2015/09/02 15:23:09","endTime":"0001/01/01 00:00:00","running":1,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"netFilesAdded":0,"netFilesUpdated":0,"netFilesDeleted":0,"netBytesAdded":0,"netBytesUpdated":0,"lbrRcsOpens":0,"lbrRcsCloses":0,"lbrRcsCheckins":0,"lbrRcsExists":0,"lbrRcsReads":0,"lbrRcsReadBytes":0,"lbrRcsWrites":0,"lbrRcsWriteBytes":0,"lbrCompressOpens":0,"lbrCompressCloses":0,"lbrCompressCheckins":0,"lbrCompressExists":0,"lbrCompressReads":0,"lbrCompressReadBytes":0,"lbrCompressWrites":0,"lbrCompressWriteBytes":0,"lbrUncompressOpens":0,"lbrUncompressCloses":0,"lbrUncompressCheckins":0,"lbrUncompressExists":0,"lbrUncompressReads":0,"lbrUncompressReadBytes":0,"lbrUncompressWrites":0,"lbrUncompressWriteBytes":0,"cmdError":false,"tables":[]}`,
		output[0])

}
