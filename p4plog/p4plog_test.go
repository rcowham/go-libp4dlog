package p4plog

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"sort"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// If you want to debug a particular test (and output debug info):
//
//	go test -run TestRemovedFromMonitorTable -args -debug
var testDebug = flag.Bool("debug", false, "Set for debug")

func parseLogLines(input string) []string {

	inchan := make(chan string, 10)

	logger := logrus.New()
	logger.Level = logrus.InfoLevel
	fp := NewP4pFileParser(logger)
	if *testDebug {
		fp.debug = 511
		logger.Level = logrus.DebugLevel
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmdChan := fp.LogParser(ctx, inchan)

	scanner := bufio.NewScanner(strings.NewReader(input))
	for scanner.Scan() {
		inchan <- scanner.Text()
	}
	close(inchan)

	output := []string{}
	for cmd := range cmdChan {
		switch cmd := cmd.(type) {
		case ProxyCommand:
			output = append(output, cmd.String())
		}
	}
	sort.Strings(output)
	return output
}

type lbrRegex struct {
	line   string
	result bool
}

// cleanJSON removes fields with a value of 0 from the JSON string.
func cleanJSON(jsonStr string) string {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(jsonStr), &result)
	if err != nil {
		return ""
	}
	cleanMap(result)
	cleanedJSON, err := json.Marshal(result)
	if err != nil {
		return ""
	}
	return string(cleanedJSON)
}

// cleanMap recursively removes fields with a value of 0 from the map.
func cleanMap(m map[string]interface{}) {
	for key, value := range m {
		switch v := value.(type) {
		case map[string]interface{}:
			cleanMap(v)
		case []interface{}:
			for _, item := range v {
				if itemMap, ok := item.(map[string]interface{}); ok {
					cleanMap(itemMap)
				}
			}
		case float64:
			if v == 0.0 {
				delete(m, key)
			}
		}
	}
}

func TestLogParse(t *testing.T) {
	testInput := `
Perforce proxy info:
	2024/09/29 04:54:20 pid 1594610 completed .212s
--- lapse .213s
--- rpc msgs/size in+out 1+2/0mb+0mb himarks 2000/2000 snd/rcv .000s/.000s
--- filetotals (svr) send/recv files+bytes 0+0mb/0+0mb
`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	assert.JSONEq(t, cleanJSON(`{"completedLapse":0.213, "endTime":"2024/09/29 04:54:20", "lineNo":2, "pid":1594610}`),
		cleanJSON(output[0]))

}

// --- proxytotals files/size svr+cache 1403+203/25.6M+254M
// --- proxytotals files/size svr+cache 0+2/0B+153K
// --- proxytotals files/size svr+cache 0+3/0B+1.4M
// --- proxytotals files/size svr+cache 0+1/0B+78.4K
// --- proxytotals files/size svr+cache 8+16/112.9K+25.7M
// --- proxytotals files/size svr+cache 431+83/7.4M+212.7M
// --- proxytotals files/size svr+cache 17+9/327.5K+1.3M
// --- proxytotals files/size svr+cache 463+114/7.9M+241.5M

func TestLogParse2(t *testing.T) {
	testInput := `
Perforce proxy info:
	2025/05/14 00:08:26 pid 1867385 completed .921s
--- lapse .921s
--- usage 1+1us 0+32io 0+0net 7732k 0pf
--- rpc msgs/size in+out 5+5/0mb+0mb himarks 2000/2000 snd/rcv .000s/.002s
--- filetotals (svr) send/recv files+bytes 0+0mb/0+0mb
--- proxy faults 0 MB 0 other 0 flushes 1 cached 0
--- proxytotals files/size svr+cache 0+0/0B+0B
--- pdb.monitor
---   pages in+out+cached 7+4+3
---   locks read/write 0/2 rows get+pos+scan put+del 0+0+0 1+1
`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	// assert.Equal(t, "", output)
	assert.JSONEq(t, cleanJSON(`{"completedLapse":0.921, "endTime":"2025/05/14 00:08:26", "lineNo":2, "pid":1867385}`),
		cleanJSON(output[0]))
}

func TestLogParse3(t *testing.T) {
	testInput := `
Perforce proxy info:
	2025/05/14 00:08:26 pid 1867385 completed .921s
--- lapse .921s
--- usage 1+1us 0+32io 0+0net 7732k 0pf
--- rpc msgs/size in+out 5+5/0mb+0mb himarks 2000/2000 snd/rcv .000s/.002s
--- proxytotals files/size svr+cache 1403+203/25.6M+254M
`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	// assert.Equal(t, "", output)
	assert.JSONEq(t, cleanJSON(`{"completedLapse":0.921, "endTime":"2025/05/14 00:08:26", "lineNo":2, "pid":1867385, "proxyTotalsCache":203, "proxyTotalsCacheBytes":2.66338304e+08, "proxyTotalsSvr":1403, "proxyTotalsSvrBytes":2.6843546e+07}`),
		cleanJSON(output[0]))
}

func TestLogParse4(t *testing.T) {
	testInput := `
Perforce proxy info:
	2025/05/14 00:08:26 pid 1867385 completed .921s
--- lapse .921s
--- usage 1+1us 0+32io 0+0net 7732k 0pf
--- rpc msgs/size in+out 5+5/0mb+0mb himarks 2000/2000 snd/rcv .000s/.002s
--- proxytotals files/size svr+cache 10+11/100B+2.5K
`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	// assert.Equal(t, "", output)
	assert.JSONEq(t, cleanJSON(`{"completedLapse":0.921, "endTime":"2025/05/14 00:08:26", "lineNo":2, "pid":1867385, "proxyTotalsCache":11, "proxyTotalsCacheBytes":2560, "proxyTotalsSvr":10, "proxyTotalsSvrBytes":100}`),
		cleanJSON(output[0]))
}

// func TestLogErrors(t *testing.T) {
// 	testInput := `
// Perforce proxy error:
// 	Date 2025/05/13 23:49:05:
// 	Connection from unknown broken.
// 	Partner exited unexpectedly.
// `
// 	output := parseLogLines(testInput)
// 	assert.Equal(t, 1, len(output))
// 	assert.JSONEq(t, cleanJSON(`{}`),
// 		cleanJSON(output[0]))
// }
