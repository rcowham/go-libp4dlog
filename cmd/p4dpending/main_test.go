package main

import (
	"bufio"
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	p4dlog "github.com/rcowham/go-libp4dlog"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

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
		switch cmd := cmd.(type) {
		case p4dlog.Command:
			output = append(output, cmd.String())
		case p4dlog.ServerEvent:
			output = append(output, cmd.String())
		}
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
	assert.JSONEq(t, cleanJSON(`{"processKey":"4d4e5096f7b732e4ce95230ef085bf51","cmd":"user-sync","pid":1616,"lineNo":2,"user":"robert","workspace":"robert-test","computeLapse":0.031,"completedLapse":0.031,"ip":"127.0.0.1","app":"Microsoft Visual Studio 2013/12.0.21005.1","args":"//...","startTime":"2015/09/02 15:23:09","endTime":"2015/09/02 15:23:09","running":1,"cmdError":false,"tables":[]}`),
		cleanJSON(output[0]))

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
	assert.JSONEq(t, cleanJSON(`{"processKey":"4d4e5096f7b732e4ce95230ef085bf51","cmd":"user-sync","pid":1616,"lineNo":2,"user":"robert","workspace":"robert-test","computeLapse":0.031,"completedLapse":0,"ip":"127.0.0.1","app":"Microsoft Visual Studio 2013/12.0.21005.1","args":"//...","startTime":"2015/09/02 15:23:09","endTime":"0001/01/01 00:00:00","running":1,"cmdError":false,"tables":[]}`),
		cleanJSON(output[0]))

}
