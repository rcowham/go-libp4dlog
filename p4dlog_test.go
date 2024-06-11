package p4dlog

import (
	"bufio"
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// func getResult(output chan string) []string {
// 	lines := []string{}
// 	for line := range output {
// 		lines = append(lines, line)
// 	}
// 	return lines
// }

func parseLogLines(input string) []string {

	inchan := make(chan string, 10)

	logger := logrus.New()
	logger.Level = logrus.InfoLevel
	fp := NewP4dFileParser(logger)
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
		output = append(output, cmd.String())
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
Perforce server info:
	2015/09/02 15:23:09 pid 1616 robert@robert-test 127.0.0.1 [Microsoft Visual Studio 2013/12.0.21005.1] 'user-sync //...'
Perforce server info:
	2015/09/02 15:23:09 pid 1616 compute end .031s
Perforce server info:
	2015/09/02 15:23:09 pid 1616 completed .031s`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	assert.JSONEq(t, cleanJSON(`{"processKey": "4d4e5096f7b732e4ce95230ef085bf51","cmd": "user-sync","pid": 1616,"lineNo": 2,"user": "robert","workspace": "robert-test","computeLapse": 0.031,"completedLapse": 0.031,"ip": "127.0.0.1","app": "Microsoft Visual Studio 2013/12.0.21005.1","args": "//...","startTime": "2015/09/02 15:23:09","endTime": "2015/09/02 15:23:09","running": 1,"cmdError": false,"tables": []}`),
		cleanJSON(output[0]))

	// Sames as above with invalid Unicode strings
	testInput = `
Perforce server info:
	2015/09/02 15:23:09 pid 1616 robert@robert-test 127.0.0.1 [Microsoft® Visual Studio® 2013/12.0.21005.1] 'user-sync //...'
Perforce server info:
	2015/09/02 15:23:09 pid 1616 compute end .031s
Perforce server info:
	2015/09/02 15:23:09 pid 1616 completed .031s`
	output = parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	assert.JSONEq(t, cleanJSON(`{"processKey":"1f360d628fb2c9fe5354b8cf5022f7bd","cmd":"user-sync","pid":1616,"lineNo":2,"user":"robert","workspace":"robert-test","computeLapse":0.031,"completedLapse":0.031,"ip":"127.0.0.1","app":"Microsoft® Visual Studio® 2013/12.0.21005.1","args":"//...","startTime":"2015/09/02 15:23:09","endTime":"2015/09/02 15:23:09","running":1,"cmdError":false,"tables":[]}`),
		cleanJSON(output[0]))

}

func TestClientLockRecords(t *testing.T) {
	testInput := `
Perforce server info:
	2017/02/15 13:46:42 pid 81805 bruno@robert_cowham-dvcs-1487082773 10.62.185.98 [p4/2016.2/LINUX26X86_64/1468155] 'user-client -d -f bruno.139631598948304.irp210-h03'
Perforce server info:
	2017/02/15 13:46:42 pid 81805 bruno@robert_cowham-dvcs-1487082773 10.62.185.98 [p4/2016.2/LINUX26X86_64/1468155] 'user-client -d -f bruno.139631598948304.irp210-h03'
--- clients/bruno%2E139631598948304%2Eirp210-h03(W)
---   total lock wait+held read/write 0ms+0ms/0ms+9ms

Perforce server info:
	2017/02/15 13:46:42 pid 81805 completed .009s 8+1us 0+1408io 0+0net 4088k 0pf
Perforce server info:
	2017/02/15 13:46:42 pid 81805 bruno@robert_cowham-dvcs-1487082773 10.62.185.98 [p4/2016.2/LINUX26X86_64/1468155] 'user-client -d -f bruno.139631598948304.irp210-h03'
--- lapse .009s
--- usage 10+11us 12+13io 14+15net 4088k 0pf
--- rpc msgs/size in+out 20+21/22mb+23mb himarks 318788/318789 snd/rcv .001s/.002s
--- db.have
---   pages in+out+cached 1+2+3
---   pages split internal+leaf 41+42
---   locks read/write 4/5 rows get+pos+scan put+del 6+7+8 9+10
---   total lock wait+held read/write 12ms+13ms/14ms+15ms
---   max lock wait+held read/write 32ms+33ms/34ms+35ms
---   peek count 20 wait+held total/max 21ms+22ms/23ms+24ms`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	assert.JSONEq(t, cleanJSON(`{"processKey":"7868f2723d35c6cb91784afa6bef4a7a","cmd":"user-client","pid":81805,"lineNo":2,"user":"bruno","workspace":"robert_cowham-dvcs-1487082773","completedLapse":0.009,"ip":"10.62.185.98","app":"p4/2016.2/LINUX26X86_64/1468155","args":"-d -f bruno.139631598948304.irp210-h03","startTime":"2017/02/15 13:46:42","endTime":"2017/02/15 13:46:42","running":1,"uCpu":10,"sCpu":11,"diskIn":12,"diskOut":13,"ipcIn":14,"ipcOut":15,"maxRss":4088,"rpcMsgsIn":20,"rpcMsgsOut":21,"rpcSizeIn":22,"rpcSizeOut":23,"rpcHimarkFwd":318788,"rpcHimarkRev":318789,"rpcSnd":0.001,"rpcRcv":0.002,"cmdError":false,"tables":[{"tableName":"have","pagesIn":1,"pagesOut":2,"pagesCached":3,"pagesSplitInternal":41,"pagesSplitLeaf":42,"readLocks":4,"writeLocks":5,"getRows":6,"posRows":7,"scanRows":8,"putRows":9,"delRows":10,"totalReadWait":12,"totalReadHeld":13,"totalWriteWait":14,"totalWriteHeld":15,"maxReadWait":32,"maxReadHeld":33,"maxWriteWait":34,"maxWriteHeld":35,"peekCount":20,"totalPeekWait":21,"totalPeekHeld":22,"maxPeekWait":23,"maxPeekHeld":24}]}`),
		cleanJSON(output[0]))
}

func TestStorageRecords(t *testing.T) {
	testInput := `
Perforce server info:
	2020/10/16 06:00:01 pid 8748 build@commander-controller 10.5.20.152 [p4/2018.1/LINUX26X86_64/1957529] 'user-client -i'
--- storageup/storageup(R)
---   total lock wait+held read/write 0ms+3ms/0ms+0ms

Perforce server info:
	2020/10/16 06:00:01 pid 8748 build@commander-controller 10.5.20.152 [p4/2018.1/LINUX26X86_64/1957529] 'user-client -i'
--- storageup/storagemasterup(R)
---   total lock wait+held read/write 0ms+3ms/0ms+0ms

Perforce server info:
	2020/10/16 06:00:01 pid 8748 completed .011s 4+4us 8+72io 0+0net 9984k 0pf 
Perforce server info:
	2020/10/16 06:00:01 pid 8748 build@commander-controller 10.5.20.152 [p4/2018.1/LINUX26X86_64/1957529] 'user-client -i'
--- lapse .012s
--- usage 4+4us 8+80io 0+0net 9984k 0pf 
--- rpc msgs/size in+out 3+5/0mb+0mb himarks 795800/318788 snd/rcv .000s/.004s
--- db.counters
---   pages in+out+cached 3+0+2
---   locks read/write 1/0 rows get+pos+scan put+del 1+0+0 0+0
`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	assert.JSONEq(t, cleanJSON(`{"processKey":"7ca020fc087e28ca774cc2267a45cedf","cmd":"user-client","pid":8748,"lineNo":2,"user":"build","workspace":"commander-controller","completedLapse":0.012,"ip":"10.5.20.152","app":"p4/2018.1/LINUX26X86_64/1957529","args":"-i","startTime":"2020/10/16 06:00:01","endTime":"2020/10/16 06:00:01","running":1,"uCpu":4,"sCpu":4,"diskIn":8,"diskOut":80,"maxRss":9984,"rpcMsgsIn":3,"rpcMsgsOut":5,"rpcHimarkFwd":795800,"rpcHimarkRev":318788,"rpcRcv":0.004,"cmdError":false,"tables":[{"tableName":"counters","pagesIn":3,"pagesCached":2,"readLocks":1,"getRows":1},{"tableName":"storagemasterup_R","totalReadHeld":3},{"tableName":"storageup_R","totalReadHeld":3}]}`),
		cleanJSON(output[0]))
}

func TestLabelRecords(t *testing.T) {
	// We don't necessarily parse the label records but don't want them being counted against previous tables.
	// So in this example the db.monitor totalWriteHeld should be 0 not 158304
	testInput := `
Perforce server info:
	2020/10/16 06:00:01 pid 8748 build@commander-controller 10.5.20.152 [p4/2018.1/LINUX26X86_64/1957529] 'user-label -i'

Perforce server info:
	2020/10/16 06:00:01 pid 8748 completed .011s 4+4us 8+72io 0+0net 9984k 0pf 
Perforce server info:
	2020/10/16 06:00:01 pid 8748 build@commander-controller 10.5.20.152 [p4/2018.1/LINUX26X86_64/1957529] 'user-label -i'
--- lapse .012s
--- usage 4+4us 8+80io 0+0net 9984k 0pf 
--- rpc msgs/size in+out 3+5/0mb+0mb himarks 795800/318788 snd/rcv .000s/.004s
--- db.monitor
---   pages in+out+cached 2+4+4096
---   locks read/write 0/2 rows get+pos+scan put+del 0+0+0 2+0
--- label/MPSS%2EDE%2E2%2E0-00348-WAIPIO_GENMD_TEST-1(W)
---   total lock wait+held read/write 0ms+0ms/0ms+158304ms
`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	assert.JSONEq(t, cleanJSON(`{"processKey":"7e3d11dfb4701f7818a630d0b2c2c1ba","cmd":"user-label","pid":8748,"lineNo":2,"user":"build","workspace":"commander-controller","completedLapse":0.012,"ip":"10.5.20.152","app":"p4/2018.1/LINUX26X86_64/1957529","args":"-i","startTime":"2020/10/16 06:00:01","endTime":"2020/10/16 06:00:01","running":1,"uCpu":4,"sCpu":4,"diskIn":8,"diskOut":80,"maxRss":9984,"rpcMsgsIn":3,"rpcMsgsOut":5,"rpcHimarkFwd":795800,"rpcHimarkRev":318788,"rpcRcv":0.004,"cmdError":false,"tables":[{"tableName":"monitor","pagesIn":2,"pagesOut":4,"pagesCached":4096,"writeLocks":2,"putRows":2}]}`),
		cleanJSON(output[0]))
	// assert.Equal(t, ``,
	// 	cleanJSON(output[0]))
}

func TestLogParseSwarm(t *testing.T) {
	testInput := `
Perforce server info:
	2016/12/21 08:39:39 pid 14769 perforce@~tmp.1482305462.13038.585a2fb6041cc1.60954329 192.168.18.31 [SWARM/2016.2/1446446] 'user-counter -u swarm-activity-fffec3dd {"type":"change","link":["change",{"change":1005814}],"user":"sahaltran05","action":"committed","target":"change 1005814","preposition":"into","description":"Mac address filtering and fixing the naming collision for the SSH and telnet libraries\n","details":null,"topic":"changes\/1005814","depotFile":null,"time":1482305978,"behalfOf":null,"projects":{"sah-automation":["sah-tests"]},"streams":["user-sahaltran05","personal-sahaltran05","project-sah-automation","group-p4altran","group-sah_app","group-sah_commun_modules","group-sah_components","group-sah_demo","group-sah_hardco","group-sah_nanterre","group-sah_nanterre_opensource","group-sah_opensource","group-sah_stbconfig","group-sah_stbconfig_dev","group-sah_system","group-sah_third_party","group-sah_validation","group-sah_wijgmaal","personal-sah4011"],"change":1005814}'
Perforce server info:
	2016/12/21 08:39:39 pid 14769 completed .003s 4+0us 0+16io 0+0net 6432k 0pf
`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	assert.JSONEq(t, cleanJSON(`{"processKey":"d0ae06fd40d95180ca403a9c30084a66","cmd":"user-counter","pid":14769,"lineNo":2,"user":"perforce","workspace":"~tmp.1482305462.13038.585a2fb6041cc1.60954329","completedLapse":0.003,"ip":"192.168.18.31","app":"SWARM/2016.2/1446446","args":"-u swarm-activity-fffec3dd","startTime":"2016/12/21 08:39:39","endTime":"2016/12/21 08:39:39","running":1,"uCpu":4,"diskOut":16,"maxRss":6432,"cmdError":false,"tables":[]}`),
		cleanJSON(output[0]))
}

func TestLogParseGitFusion(t *testing.T) {
	testInput := `
Perforce server info:
	2016/10/19 12:01:08 pid 10664 git-fusion-user@GF-TRIGGER-567d67de-962 10.100.104.199 [p4/2016.1/NTX64/1396108] 'user-key git-fusion-reviews-common-lock-owner {"server_id": "p4gf_submit_trigger", "process_id": 5068, "start_time": "2016-10-19 12:01:08"}'
Perforce server info:
	2016/10/19 12:01:08 pid 10664 git-fusion-user@GF-TRIGGER-567d67de-962 10.100.104.199 [p4/2016.1/NTX64/1396108] 'user-key git-fusion-reviews-common-lock-owner {"server_id": "p4gf_submit_trigger", "process_id": 5068, "start_time": "2016-10-19 12:01:08"}'
--- lapse .875s
--- rpc msgs/size in+out 2+3/0mb+0mb himarks 523588/523588 snd/rcv .000s/.015s
--- db.nameval
---   pages in+out+cached 6+4+4
---   locks read/write 0/1 rows get+pos+scan put+del 0+0+0 1+0
---   total lock wait+held read/write 0ms+0ms/16ms+15ms
--- db.user
---   pages in+out+cached 4+0+3
---   locks read/write 1/0 rows get+pos+scan put+del 1+0+0 0+0
---   total lock wait+held read/write 0ms+16ms/0ms+0ms
--- db.group
---   pages in+out+cached 7+0+6
---   locks read/write 1/0 rows get+pos+scan put+del 0+3+67 0+0
---   total lock wait+held read/write 0ms+15ms/0ms+0ms
--- db.trigger
---   pages in+out+cached 21+0+20
---   locks read/write 1/0 rows get+pos+scan put+del 0+1+486 0+0
---   total lock wait+held read/write 0ms+47ms/0ms+0ms
--- db.protect
---   pages in+out+cached 282+0+96
---   locks read/write 1/0 rows get+pos+scan put+del 0+1+14495 0+0
---   total lock wait+held read/write 0ms+641ms/0ms+0ms
Perforce server info:
	2016/10/19 12:01:09 pid 10664 completed .844s`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	assert.JSONEq(t, cleanJSON(`{"processKey":"1eec998ae9cc1ce44058f4503a01f2c0","cmd":"user-key","pid":10664,"lineNo":2,"user":"git-fusion-user","workspace":"GF-TRIGGER-567d67de-962","completedLapse":0.844,"ip":"10.100.104.199","app":"p4/2016.1/NTX64/1396108","args":"git-fusion-reviews-common-lock-owner","startTime":"2016/10/19 12:01:08","endTime":"2016/10/19 12:01:09","running":1,"rpcMsgsIn":2,"rpcMsgsOut":3,"rpcHimarkFwd":523588,"rpcHimarkRev":523588,"rpcRcv":0.015,"cmdError":false,"tables":[{"tableName":"group","pagesIn":7,"pagesCached":6,"readLocks":1,"posRows":3,"scanRows":67,"totalReadHeld":15},{"tableName":"nameval","pagesIn":6,"pagesOut":4,"pagesCached":4,"writeLocks":1,"putRows":1,"totalWriteWait":16,"totalWriteHeld":15},{"tableName":"protect","pagesIn":282,"pagesCached":96,"readLocks":1,"posRows":1,"scanRows":14495,"totalReadHeld":641},{"tableName":"trigger","pagesIn":21,"pagesCached":20,"readLocks":1,"posRows":1,"scanRows":486,"totalReadHeld":47},{"tableName":"user","pagesIn":4,"pagesCached":3,"readLocks":1,"getRows":1,"totalReadHeld":16}]}`),
		cleanJSON(output[0]))
}

func TestLongCommand(t *testing.T) {
	testInput := `
Perforce server info:
	2015/09/02 16:43:36 pid 4500 robert@robert-test 127.0.0.1 [Microsoft Visual Studio 2013/12.0.21005.1] 'user-reconcile -eadf -c 12253 c:\temp\robert-test\test\VEER!-%-#-@-$-&-(-)\fred - Copy.txt c:\temp\robert-test\test\VEER!-%-#-@-$-&-(-)\fred - Copy.txt c:\temp\robert-test\test\VEER!-%-#-@-$-&-(-)\fred - Copy.txt c:\temp\robert-test\test\VEER!-%-#-@-$-&-(-)\fred - Copy.txt'
Perforce server info:
	2015/09/02 16:43:36 pid 4500 completed .187s
Perforce server info:
	2015/09/02 16:43:36 pid 4500 robert@robert-test 127.0.0.1 [Microsoft Visual Studio 2013/12.0.21005.1] 'user-reconcile -eadf -c 12253 c:\temp\robert-test\test\VEER!-%-#-@-$-&-(-)\fred - Copy.txt c:\temp\robert-test\test\VEER!-%-#-@-$-&-(-)\fred - Copy.txt c:\temp\robert-test\test\VEER!-%-#-@-$-&-(-)\fred - Copy.txt c:\temp\robert-test\test\VEER!-%-#-@-$-&-(-)\fred - Copy.txt'
--- clients/robert-test(W)
---   total lock wait+held read/write 0ms+0ms/0ms+172ms
`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	//assert.Equal(t, "", output[0])
	assert.JSONEq(t, cleanJSON(`{"processKey":"e2bf456007fe305acdae759996dbbeb9","cmd":"user-reconcile","pid":4500,"lineNo":2,"user":"robert","workspace":"robert-test","completedLapse":0.187,"ip":"127.0.0.1","app":"Microsoft Visual Studio 2013/12.0.21005.1","args":"-eadf -c 12253 c:\\temp\\robert-test\\test\\VEER!-%-#-@-$-\u0026-(-)\\fred - Copy.txt c:\\temp\\robert-test\\test\\VEER!-%-#-@-$-\u0026-(-)\\fred - Copy.txt c:\\temp\\robert-test\\test\\VEER!-%-#-@-$-\u0026-(-)\\fred - Copy.txt c:\\temp\\robert-test\\test\\VEER!-%-#-@-$-\u0026-(-)\\fred - Copy.txt","startTime":"2015/09/02 16:43:36","endTime":"2015/09/02 16:43:36","running":1,"cmdError":false,"tables":[]}`),
		cleanJSON(output[0]))
}

func TestNetworkEstimates(t *testing.T) {
	testInput := `
Perforce server info:
	2017/02/15 10:11:30 pid 4917 bruno@bruno.140451462678608 10.62.185.99 [unnamed p4-python script/v81] 'user-have'
Perforce server info:
	2017/02/15 10:11:30 pid 4917 completed .002s 2+0us 0+0io 0+0net 8932k 0pf
Perforce server info:
	2017/02/15 10:11:30 pid 4917 bruno@bruno.140451462678608 10.62.185.99 [unnamed p4-python script/v81] 'user-sync //bruno.140451462678608/...'
Perforce server info:
	2017/02/15 10:11:30 pid 4917 compute end .020s 16+3us 0+0io 0+0net 8964k 0pf
Perforce server info:
	Server network estimates: files added/updated/deleted=1/2/3, bytes added/updated=111325/813906
Perforce server info:
	2017/02/15 10:11:30 pid 4917 completed .034s 19+4us 0+8io 0+0net 8996k 0pf`
	output := parseLogLines(testInput)
	assert.Equal(t, 2, len(output))
	assert.JSONEq(t, cleanJSON(`{"processKey":"4964a5f82541f47985f0965ab47c1e39","cmd":"user-have","pid":4917,"lineNo":2,"user":"bruno","workspace":"bruno.140451462678608","completedLapse":0.002,"ip":"10.62.185.99","app":"unnamed p4-python script/v81","args":"","startTime":"2017/02/15 10:11:30","endTime":"2017/02/15 10:11:30","running":1,"uCpu":2,"maxRss":8932,"cmdError":false,"tables":[]}`),
		cleanJSON(output[0]))
	assert.JSONEq(t, cleanJSON(`{"processKey":"7c65428ac3b32f6f42f84ead5694ffb4","cmd":"user-sync","pid":4917,"lineNo":6,"user":"bruno","workspace":"bruno.140451462678608","computeLapse":0.02,"completedLapse":0.034,"ip":"10.62.185.99","app":"unnamed p4-python script/v81","args":"//bruno.140451462678608/...","startTime":"2017/02/15 10:11:30","endTime":"2017/02/15 10:11:30","running":1,"uCpu":19,"sCpu":4,"diskOut":8,"maxRss":8996,"netFilesAdded":1,"netFilesUpdated":2,"netFilesDeleted":3,"netBytesAdded":111325,"netBytesUpdated":813906,"cmdError":false,"tables":[]}`),
		cleanJSON(output[1]))
}

// Thes get duplicate pids in same second and have no completed record
func TestRemoteFileFetches(t *testing.T) {
	testInput := `
Perforce server info:
	2017/03/06 11:53:50 pid 113249 serviceUser@unknown 10.62.185.99 [p4d/2016.2/LINUX26X86_64/1468155] 'rmt-FileFetch'
--- rpc msgs/size in+out 0+2/0mb+0mb himarks 318788/318788 snd/rcv .000s/.000s
--- db.user
---   pages in+out+cached 2+0+2
---   locks read/write 1/0 rows get+pos+scan put+del 1+0+0 0+0

Perforce server info:
	2017/03/06 11:53:50 pid 113249 serviceUser@unknown 10.62.185.99 [p4d/2016.2/LINUX26X86_64/1468155] 'rmt-FileFetch'
--- rpc msgs/size in+out 0+2/0mb+0mb himarks 318788/318788 snd/rcv .000s/.000s
--- db.user
---   pages in+out+cached 1+0+2
---   locks read/write 1/0 rows get+pos+scan put+del 1+0+0 0+0
`
	output := parseLogLines(testInput)
	assert.Equal(t, 2, len(output))
	assert.JSONEq(t, cleanJSON(`{"processKey":"bea947227d9ec7f4300a0ea889886934","cmd":"rmt-FileFetch","pid":113249,"lineNo":2,"user":"serviceUser","workspace":"unknown","ip":"10.62.185.99","app":"p4d/2016.2/LINUX26X86_64/1468155","args":"","startTime":"2017/03/06 11:53:50","endTime":"2017/03/06 11:53:50","rpcMsgsOut":2,"rpcHimarkFwd":318788,"rpcHimarkRev":318788,"cmdError":false,"tables":[{"tableName":"user","pagesIn":2,"pagesCached":2,"readLocks":1,"getRows":1}]}`),
		cleanJSON(output[0]))
	assert.JSONEq(t, cleanJSON(`{"processKey":"bea947227d9ec7f4300a0ea889886934.9","cmd":"rmt-FileFetch","pid":113249,"lineNo":9,"user":"serviceUser","workspace":"unknown","ip":"10.62.185.99","app":"p4d/2016.2/LINUX26X86_64/1468155","args":"","startTime":"2017/03/06 11:53:50","endTime":"2017/03/06 11:53:50","rpcMsgsOut":2,"rpcHimarkFwd":318788,"rpcHimarkRev":318788,"cmdError":false,"tables":[{"tableName":"user","pagesIn":1,"pagesCached":2,"readLocks":1,"getRows":1}]}`),
		cleanJSON(output[1]))
}

// These test values used in 2 tests
var multiInput = `
Perforce server info:
	2015/09/02 15:23:09 pid 1616 robert@robert-test 127.0.0.1 [p4/2016.2/LINUX26X86_64/1598668] 'user-sync //...'
Perforce server info:
	2015/09/02 15:23:09 pid 1616 compute end .031s
Perforce server info:
	2015/09/02 15:23:09 pid 1534 fred@fred-test 127.0.0.1 [p4/2016.2/LINUX26X86_64/1598668] 'user-sync //...'
Perforce server info:
	2015/09/02 15:23:09 pid 1534 compute end .021s
Perforce server info:
	2015/09/02 15:23:09 pid 1616 completed .031s
Perforce server info:
	2015/09/02 15:23:09 pid 1534 completed .041s`
var multiExp1 = `{"processKey":"f9a64670da4d77a44225be236974bc8b","cmd":"user-sync","pid":1616,"lineNo":2,"user":"robert","workspace":"robert-test","computeLapse":0.031,"completedLapse":0.031,"ip":"127.0.0.1","app":"p4/2016.2/LINUX26X86_64/1598668","args":"//...","startTime":"2015/09/02 15:23:09","endTime":"2015/09/02 15:23:09","running":1,"cmdError":false,"tables":[]}`
var multiExp2 = `{"processKey":"2908cdb35e4b82dae3d0b403ef0c3bbf","cmd":"user-sync","pid":1534,"lineNo":6,"user":"fred","workspace":"fred-test","computeLapse":0.021,"completedLapse":0.041,"ip":"127.0.0.1","app":"p4/2016.2/LINUX26X86_64/1598668","args":"//...","startTime":"2015/09/02 15:23:09","endTime":"2015/09/02 15:23:09","running":2,"cmdError":false,"tables":[]}`

func TestLogParseMulti(t *testing.T) {
	output := parseLogLines(multiInput)
	assert.Equal(t, 2, len(output))
	sort.Strings(output)
	//assert.Equal(t, "", output[0])
	assert.JSONEq(t, cleanJSON(multiExp1), cleanJSON(output[1]))
	assert.JSONEq(t, cleanJSON(multiExp2), cleanJSON(output[0]))
}

func TestLogParseSubmit(t *testing.T) {
	testInput := `
Perforce server info:
	2018/06/10 23:30:06 pid 25568 fred@lon_ws 10.1.2.3 [p4/2016.2/LINUX26X86_64/1598668] 'user-submit -i'

Perforce server info:
	2018/06/10 23:30:07 pid 25568 completed .178s 96+17us 0+208io 0+0net 15668k 0pf
Perforce server info:
	2018/06/10 23:30:07 pid 25568 fred@lon_ws 10.1.2.3 [p4/2016.2/LINUX26X86_64/1598668] 'dm-SubmitChange'

Perforce server info:
	2018/06/10 23:30:07 pid 25568 compute end .252s 35+6us 0+8io 0+0net 49596k 0pf

Perforce server info:
	2018/06/10 23:30:08 pid 25568 completed 1.38s 490+165us 0+178824io 0+0net 127728k 0pf
Perforce server info:
	2018/06/10 23:30:08 pid 25568 fred@lon_ws 10.1.2.3 [p4/2016.2/LINUX26X86_64/1598668] 'dm-CommitSubmit'

Perforce server info:
	2018/06/10 23:30:08 pid 25568 fred@lon_ws 10.1.2.3 [p4/2016.2/LINUX26X86_64/1598668] 'dm-CommitSubmit'
--- meta/commit(W)
---   total lock wait+held read/write 0ms+0ms/0ms+795ms

Perforce server info:
	2018/06/10 23:30:08 pid 25568 fred@lon_ws 10.1.2.3 [p4/2016.2/LINUX26X86_64/1598668] 'dm-CommitSubmit'
--- clients/MCM_client_184%2E51%2E33%2E29_prod_prefix1(W)
---   total lock wait+held read/write 0ms+0ms/0ms+1367ms

Perforce server info:
	2018/06/10 23:30:09 pid 25568 completed 1.38s 34+61us 59680+59904io 0+0net 127728k 1pf
Perforce server info:
	2018/06/10 23:30:08 pid 25568 fred@lon_ws 10.1.2.3 [p4/2016.2/LINUX26X86_64/1598668] 'dm-CommitSubmit'
--- db.integed
---   total lock wait+held read/write 0ms+0ms/0ms+795ms
--- db.archmap
---   total lock wait+held read/write 0ms+0ms/0ms+780ms

`
	output := parseLogLines(testInput)
	assert.Equal(t, 3, len(output))
	//assert.Equal(t, "", output[1])
	assert.JSONEq(t, cleanJSON(`{"processKey":"128e10d7fe570c2d2f5f7f03e1186827","cmd":"dm-CommitSubmit","pid":25568,"lineNo":15,"user":"fred","workspace":"lon_ws","completedLapse":1.38,"ip":"10.1.2.3","app":"p4/2016.2/LINUX26X86_64/1598668","args":"","startTime":"2018/06/10 23:30:08","endTime":"2018/06/10 23:30:09","running":1,"uCpu":34,"sCpu":61,"diskIn":59680,"diskOut":59904,"maxRss":127728,"pageFaults":1,"cmdError":false,"tables":[{"tableName":"archmap","totalWriteHeld":780},{"tableName":"integed","totalWriteHeld":795}]}`),
		cleanJSON(output[0]))
	assert.JSONEq(t, cleanJSON(`{"processKey":"465f0a630b021d3c695e90924a757b75","cmd":"user-submit","pid":25568,"lineNo":2,"user":"fred","workspace":"lon_ws","completedLapse":0.178,"ip":"10.1.2.3","app":"p4/2016.2/LINUX26X86_64/1598668","args":"-i","startTime":"2018/06/10 23:30:06","endTime":"2018/06/10 23:30:07","running":1,"uCpu":96,"sCpu":17,"diskOut":208,"maxRss":15668,"cmdError":false,"tables":[]}`),
		cleanJSON(output[1]))
	assert.JSONEq(t, cleanJSON(`{"processKey":"78dbd54644e624a9c6f5c338a0864d2a","cmd":"dm-SubmitChange","pid":25568,"lineNo":7,"user":"fred","workspace":"lon_ws","computeLapse":0.252,"completedLapse":1.38,"ip":"10.1.2.3","app":"p4/2016.2/LINUX26X86_64/1598668","args":"","startTime":"2018/06/10 23:30:07","endTime":"2018/06/10 23:30:08","running":1,"uCpu":490,"sCpu":165,"diskOut":178824,"maxRss":127728,"cmdError":false,"tables":[]}`),
		cleanJSON(output[2]))

}

func TestLogParseSubmitMultilineDesc(t *testing.T) {
	// p4 submit and populate can take a -d flag and end up with multiline descriptions - annoying!
	testInput := `
Perforce server info:
	2018/06/10 23:30:06 pid 25568 fred@lon_ws 10.1.2.3 [p4/2016.2/LINUX26X86_64/1598668] 'user-submit -d First line
Second line
Third line
'

Perforce server info:
	2018/06/10 23:30:07 pid 25568 completed .178s 96+17us 0+208io 0+0net 15668k 0pf
Perforce server info:
	2018/06/10 23:30:07 pid 25568 fred@lon_ws 10.1.2.3 [p4/2016.2/LINUX26X86_64/1598668] 'dm-SubmitChange'

Perforce server info:
	2018/06/10 23:30:07 pid 25568 compute end .252s 35+6us 0+8io 0+0net 49596k 0pf

Perforce server info:
	2018/06/10 23:30:08 pid 25568 completed 1.38s 490+165us 0+178824io 0+0net 127728k 0pf
Perforce server info:
	2018/06/10 23:30:08 pid 25568 fred@lon_ws 10.1.2.3 [p4/2016.2/LINUX26X86_64/1598668] 'dm-CommitSubmit'

Perforce server info:
	2018/06/10 23:30:08 pid 25568 fred@lon_ws 10.1.2.3 [p4/2016.2/LINUX26X86_64/1598668] 'dm-CommitSubmit'
--- meta/commit(W)
---   total lock wait+held read/write 0ms+0ms/0ms+795ms

Perforce server info:
	2018/06/10 23:30:08 pid 25568 fred@lon_ws 10.1.2.3 [p4/2016.2/LINUX26X86_64/1598668] 'dm-CommitSubmit'
--- clients/MCM_client_184%2E51%2E33%2E29_prod_prefix1(W)
---   total lock wait+held read/write 0ms+0ms/0ms+1367ms

Perforce server info:
	2018/06/10 23:30:09 pid 25568 completed 1.38s 34+61us 59680+59904io 0+0net 127728k 1pf
Perforce server info:
	2018/06/10 23:30:08 pid 25568 fred@lon_ws 10.1.2.3 [p4/2016.2/LINUX26X86_64/1598668] 'dm-CommitSubmit'
--- db.integed
---   total lock wait+held read/write 0ms+0ms/0ms+795ms
--- db.archmap
---   total lock wait+held read/write 0ms+0ms/0ms+780ms

`
	output := parseLogLines(testInput)
	assert.Equal(t, 3, len(output))
	assert.JSONEq(t, cleanJSON(`{"processKey":"128e10d7fe570c2d2f5f7f03e1186827","cmd":"dm-CommitSubmit","pid":25568,"lineNo":18,"user":"fred","workspace":"lon_ws","completedLapse":1.38,"ip":"10.1.2.3","app":"p4/2016.2/LINUX26X86_64/1598668","args":"","startTime":"2018/06/10 23:30:08","endTime":"2018/06/10 23:30:09","running":1,"uCpu":34,"sCpu":61,"diskIn":59680,"diskOut":59904,"maxRss":127728,"pageFaults":1,"cmdError":false,"tables":[{"tableName":"archmap","totalWriteHeld":780},{"tableName":"integed","totalWriteHeld":795}]}`),
		cleanJSON(output[0]))
	assert.JSONEq(t, cleanJSON(`{"processKey":"78dbd54644e624a9c6f5c338a0864d2a","cmd":"dm-SubmitChange","pid":25568,"lineNo":10,"user":"fred","workspace":"lon_ws","computeLapse":0.252,"completedLapse":1.38,"ip":"10.1.2.3","app":"p4/2016.2/LINUX26X86_64/1598668","args":"","startTime":"2018/06/10 23:30:07","endTime":"2018/06/10 23:30:08","running":1,"uCpu":490,"sCpu":165,"diskOut":178824,"maxRss":127728,"cmdError":false,"tables":[]}`),
		cleanJSON(output[1]))
	assert.JSONEq(t, cleanJSON(`{"processKey":"954a5899d56e015d5080e4f8ef7f9e39","cmd":"user-submit","pid":25568,"lineNo":2,"user":"fred","workspace":"lon_ws","completedLapse":0.178,"ip":"10.1.2.3","app":"p4/2016.2/LINUX26X86_64/1598668","args":" -d First line","startTime":"2018/06/10 23:30:06","endTime":"2018/06/10 23:30:07","running":1,"uCpu":96,"sCpu":17,"diskOut":208,"maxRss":15668,"cmdError":false,"tables":[]}`),
		cleanJSON(output[2]))
	// assert.Equal(t, `asdf`,
	// 	output[3])
}

func TestPopulateMultilineDesc(t *testing.T) {
	// p4 submit and populate can take a -d flag and end up with multiline descriptions - annoying!
	testInput := `
Perforce server info:
	2022/12/21 18:10:48 pid 36276 fred@fred-dvcs-1671638968 unknown [p4/2021.1/MACOSX1015X86_64/2156517] 'user-populate -d    First line
	Second line
	 //stream/main/... //stream/dev/...'
Perforce server info:
	2022/12/21 18:10:48 pid 36276 fred@fred-dvcs-1671638968 unknown [p4/2021.1/MACOSX1015X86_64/2156517] 'user-populate -d    First line
	Second line
	 //stream/main/... //stream/dev/...'
--- meta/commit(W)
---   total lock wait+held read/write 0ms+0ms/0ms+14ms

Perforce server info:
	2022/12/21 18:10:48 pid 36276 fred@fred-dvcs-1671638968 unknown [p4/2021.1/MACOSX1015X86_64/2156517] 'user-populate -d    First line
	Second line
	 //stream/main/... //stream/dev/...'
--- storageup/storagemasterup(R)
---   total lock wait+held read/write 0ms+15ms/0ms+0ms

Perforce server info:
	2022/12/21 18:10:48 pid 36276 completed .019s 0+3us 0+0io 0+0net 8564736k 9pf
Perforce server info:
	2022/12/21 18:10:48 pid 36276 fred@fred-dvcs-1671638968 unknown [p4/2021.1/MACOSX1015X86_64/2156517] 'user-populate -d    First line
	Second line
	 //stream/main/... //stream/dev/...'
--- lapse .020s
--- usage 0+3us 0+0io 0+0net 8577024k 9pf
--- rpc msgs/size in+out 0+1/0mb+0mb himarks 2000/2000 snd/rcv .000s/.000s
--- db.counters
---   pages in+out+cached 14+6+2
---   locks read/write 4/4 rows get+pos+scan put+del 7+0+0 2+0
---   total lock wait+held read/write 0ms+0ms/0ms+4ms
---   max lock wait+held read/write 0ms+0ms/0ms+4ms
--- db.logger
---   pages in+out+cached 3+0+1
---   locks read/write 0/1 rows get+pos+scan put+del 0+0+0 0+0
--- db.stream
---   pages in+out+cached 8+3+2
---   locks read/write 4/1 rows get+pos+scan put+del 3+6+6 1+0

`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	assert.JSONEq(t, cleanJSON(`{"processKey":"c3ddb95f03f30b508e0e96dd8754b419","cmd":"user-populate","pid":36276,"lineNo":2,"user":"fred","workspace":"fred-dvcs-1671638968","completedLapse":0.02,"ip":"unknown","app":"p4/2021.1/MACOSX1015X86_64/2156517","args":" -d    First line","startTime":"2022/12/21 18:10:48","endTime":"2022/12/21 18:10:48","running":1,"sCpu":3,"maxRss":8577024,"pageFaults":9,"rpcMsgsOut":1,"rpcHimarkFwd":2000,"rpcHimarkRev":2000,"cmdError":false,"tables":[{"tableName":"counters","pagesIn":14,"pagesOut":6,"pagesCached":2,"readLocks":4,"writeLocks":4,"getRows":7,"putRows":2,"totalWriteHeld":4,"maxWriteHeld":4},{"tableName":"logger","pagesIn":3,"pagesCached":1,"writeLocks":1,"getRows":0},{"tableName":"storagemasterup_R","totalReadHeld":15},{"tableName":"stream","pagesIn":8,"pagesOut":3,"pagesCached":2,"readLocks":4,"writeLocks":1,"getRows":3,"posRows":6,"scanRows":6,"putRows":1}]}`),
		cleanJSON(output[0]))
}

func TestLogDuplicatePids(t *testing.T) {
	testInput := `
Perforce server info:
	2016/10/19 14:53:48 pid 4496 lcheng@lcheng 10.100.72.195 [P4V/NTX64/2014.1/888424/v76] 'user-change -o'

Perforce server info:
	2016/10/19 14:53:48 pid 4496 completed .015s
Perforce server info:
	2016/10/19 14:53:48 pid 4496 lcheng@lcheng 10.100.72.195 [P4V/NTX64/2014.1/888424/v76] 'user-change -o'
--- lapse .015s
--- rpc msgs/size in+out 0+1/0mb+0mb himarks 523588/64836 snd/rcv .000s/.000s
--- db.user
---   pages in+out+cached 1+0+3
---   locks read/write 1/0 rows get+pos+scan put+del 1+0+0 0+0
--- db.group
---   pages in+out+cached 1+0+7
---   locks read/write 1/0 rows get+pos+scan put+del 0+6+11 0+0

Perforce server info:
	2016/10/19 14:53:48 pid 4496 lcheng@lcheng 10.100.72.195 [P4V/NTX64/2014.1/888424/v76] 'user-change -o'

Perforce server info:
	2016/10/19 14:53:48 pid 4496 completed .016s
Perforce server info:
	2016/10/19 14:53:48 pid 4496 lcheng@lcheng 10.100.72.195 [P4V/NTX64/2014.1/888424/v76] 'user-change -o'
--- lapse .016s
--- rpc msgs/size in+out 0+1/0mb+0mb himarks 523588/64836 snd/rcv .000s/.000s
--- db.user
---   pages in+out+cached 1+0+3
---   locks read/write 1/0 rows get+pos+scan put+del 1+0+0 0+0
--- db.group
---   pages in+out+cached 1+0+7
---   locks read/write 1/0 rows get+pos+scan put+del 0+6+11 0+0
`
	output := parseLogLines(testInput)
	assert.Equal(t, 2, len(output))
	assert.JSONEq(t, cleanJSON(`{"processKey":"9b2bf87ce1b8e88d0d89cf44cffc4a8c","cmd":"user-change","pid":4496,"lineNo":2,"user":"lcheng","workspace":"lcheng","completedLapse":0.015,"ip":"10.100.72.195","app":"P4V/NTX64/2014.1/888424/v76","args":"-o","startTime":"2016/10/19 14:53:48","endTime":"2016/10/19 14:53:48","running":1,"rpcMsgsOut":1,"rpcHimarkFwd":523588,"rpcHimarkRev":64836,"cmdError":false,"tables":[{"tableName":"group","pagesIn":1,"pagesCached":7,"readLocks":1,"posRows":6,"scanRows":11},{"tableName":"user","pagesIn":1,"pagesCached":3,"readLocks":1,"getRows":1}]}`),
		cleanJSON(output[0]))
	assert.JSONEq(t, cleanJSON(`{"processKey":"9b2bf87ce1b8e88d0d89cf44cffc4a8c.18","cmd":"user-change","pid":4496,"lineNo":18,"user":"lcheng","workspace":"lcheng","completedLapse":0.016,"ip":"10.100.72.195","app":"P4V/NTX64/2014.1/888424/v76","args":"-o","startTime":"2016/10/19 14:53:48","endTime":"2016/10/19 14:53:48","running":1,"rpcMsgsOut":1,"rpcHimarkFwd":523588,"rpcHimarkRev":64836,"cmdError":false,"tables":[{"tableName":"group","pagesIn":1,"pagesCached":7,"readLocks":1,"posRows":6,"scanRows":11},{"tableName":"user","pagesIn":1,"pagesCached":3,"readLocks":1,"getRows":1}]}`),
		cleanJSON(output[1]))
}

func TestLogTriggerEntries(t *testing.T) {
	testInput := `
Perforce server info:
	2017/12/07 15:00:21 pid 148469 Fred@LONWS 10.40.16.14/10.40.48.29 [3DSMax/1.0.0.0] 'user-change -i' trigger swarm.changesave
lapse .044s
Perforce server info:
	2017/12/07 15:00:21 pid 148469 completed .413s 7+4us 0+584io 0+0net 4580k 0pf
Perforce server info:
	2017/12/07 15:00:21 pid 148469 Fred@LONWS 10.40.16.14/10.40.48.29 [3DSMax/1.0.0.0] 'user-change -i'
--- lapse .413s
--- usage 10+11us 12+13io 14+15net 4088k 22pf
--- rpc msgs/size in+out 20+21/22mb+23mb himarks 318788/318789 snd/rcv .001s/.002s
--- db.counters
---   pages in+out+cached 6+3+2
---   pages split internal+leaf 41+42
---   locks read/write 0/2 rows get+pos+scan put+del 2+0+0 1+0
`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	//assert.Equal(t, "", output[0])
	assert.JSONEq(t, cleanJSON(`{"processKey":"25aeba7a5658170fea61117076fa00d5","cmd":"user-change","pid":148469,"lineNo":2,"user":"Fred","workspace":"LONWS","completedLapse":0.413,"ip":"10.40.16.14/10.40.48.29","app":"3DSMax/1.0.0.0","args":"-i","startTime":"2017/12/07 15:00:21","endTime":"2017/12/07 15:00:21","running":1,"uCpu":10,"sCpu":11,"diskIn":12,"diskOut":13,"ipcIn":14,"ipcOut":15,"maxRss":4088,"pageFaults":22,"rpcMsgsIn":20,"rpcMsgsOut":21,"rpcSizeIn":22,"rpcSizeOut":23,"rpcHimarkFwd":318788,"rpcHimarkRev":318789,"rpcSnd":0.001,"rpcRcv":0.002,"cmdError":false,"tables":[{"tableName":"counters","pagesIn":6,"pagesOut":3,"pagesCached":2,"pagesSplitInternal":41,"pagesSplitLeaf":42,"writeLocks":2,"getRows":2,"putRows":1},{"tableName":"trigger_swarm.changesave","triggerLapse":0.044}]}`),
		cleanJSON(output[0]))
}

func TestLogChangeI(t *testing.T) {
	testInput := `
Perforce server info:
	2017/12/07 15:00:21 pid 148469 fred@LONWS 10.40.16.14/10.40.48.29 [3DSMax/1.0.0.0] 'user-change -i' trigger swarm.changesave
lapse .044s
Perforce server info:
	2017/12/07 15:00:21 pid 148469 completed .413s 7+4us 0+584io 0+0net 4580k 0pf
Perforce server info:
	2017/12/07 15:00:21 pid 148469 fred@LONWS 10.40.16.14/10.40.48.29 [3DSMax/1.0.0.0] 'user-change -i'
--- lapse .413s
--- usage 10+11us 12+13io 14+15net 4088k 22pf
--- rpc msgs/size in+out 20+21/22mb+23mb himarks 318788/318789 snd/rcv .001s/.002s
--- db.counters
---   pages in+out+cached 6+3+2
---   locks read/write 0/2 rows get+pos+scan put+del 2+0+0 1+0

Perforce server info:
	2018/06/10 23:30:08 pid 25568 fred@lon_ws 10.1.2.3 [p4/2016.2/LINUX26X86_64/1598668] 'dm-CommitSubmit'

Perforce server info:
	2018/06/10 23:30:08 pid 25568 fred@lon_ws 10.1.2.3 [p4/2016.2/LINUX26X86_64/1598668] 'dm-CommitSubmit'
--- meta/commit(W)
---   total lock wait+held read/write 0ms+0ms/0ms+795ms

Perforce server info:
	2018/06/10 23:30:08 pid 25568 fred@lon_ws 10.1.2.3 [p4/2016.2/LINUX26X86_64/1598668] 'dm-CommitSubmit'
--- clients/MCM_client_184%2E51%2E33%2E29_prod_prefix1(W)
---   total lock wait+held read/write 0ms+0ms/0ms+1367ms

Perforce server info:
	2018/06/10 23:30:09 pid 25568 completed 1.38s 34+61us 59680+59904io 0+0net 127728k 1pf
Perforce server info:
	2018/06/10 23:30:08 pid 25568 fred@lon_ws 10.1.2.3 [p4/2016.2/LINUX26X86_64/1598668] 'dm-CommitSubmit'
--- db.integed
---   total lock wait+held read/write 0ms+0ms/0ms+795ms
--- db.archmap
---   total lock wait+held read/write 0ms+0ms/0ms+780ms
`
	output := parseLogLines(testInput)
	assert.Equal(t, 2, len(output))
	//assert.Equal(t, "", output[1])
	assert.JSONEq(t, cleanJSON(`{"processKey":"128e10d7fe570c2d2f5f7f03e1186827","cmd":"dm-CommitSubmit","pid":25568,"lineNo":16,"user":"fred","workspace":"lon_ws","completedLapse":1.38,"ip":"10.1.2.3","app":"p4/2016.2/LINUX26X86_64/1598668","args":"","startTime":"2018/06/10 23:30:08","endTime":"2018/06/10 23:30:09","running":1,"uCpu":34,"sCpu":61,"diskIn":59680,"diskOut":59904,"maxRss":127728,"pageFaults":1,"cmdError":false,"tables":[{"tableName":"archmap","totalWriteHeld":780},{"tableName":"integed","totalWriteHeld":795}]}`),
		cleanJSON(output[0]))
	assert.JSONEq(t, cleanJSON(`{"processKey":"441371d8e17558bfb8e6cf7c1ca7b3ac","cmd":"user-change","pid":148469,"lineNo":2,"user":"fred","workspace":"LONWS","completedLapse":0.413,"ip":"10.40.16.14/10.40.48.29","app":"3DSMax/1.0.0.0","args":"-i","startTime":"2017/12/07 15:00:21","endTime":"2017/12/07 15:00:21","running":1,"uCpu":10,"sCpu":11,"diskIn":12,"diskOut":13,"ipcIn":14,"ipcOut":15,"maxRss":4088,"pageFaults":22,"rpcMsgsIn":20,"rpcMsgsOut":21,"rpcSizeIn":22,"rpcSizeOut":23,"rpcHimarkFwd":318788,"rpcHimarkRev":318789,"rpcSnd":0.001,"rpcRcv":0.002,"cmdError":false,"tables":[{"tableName":"counters","pagesIn":6,"pagesOut":3,"pagesCached":2,"writeLocks":2,"getRows":2,"putRows":1},{"tableName":"trigger_swarm.changesave","triggerLapse":0.044}]}`),
		cleanJSON(output[1]))
}

func TestLongLapse(t *testing.T) {
	testInput := `
Perforce server info:
	2017/12/07 15:00:21 pid 148469 fred@LONWS 10.40.16.14 [3DSMax/1.0.0.0] 'user-files //depot/....3ds'
Perforce server info:
	2017/12/07 15:00:23 pid 148469 completed 2.01s 7+4us 0+584io 0+0net 4580k 0pf
Perforce server info:
	2017/12/07 15:00:21 pid 148469 fred@LONWS 10.40.16.14 [3DSMax/1.0.0.0] 'user-files //depot/....3ds'
--- lapse 2.02s
--- usage 10+11us 12+13io 14+15net 4088k 22pf
--- memory cmd/proc 1mb/2mb
`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	//assert.Equal(t, "", output[0])
	assert.JSONEq(t, cleanJSON(`{"processKey":"f00da0667f738b28e706360f6997741e","cmd":"user-files","pid":148469,"lineNo":2,"user":"fred","workspace":"LONWS","completedLapse":2.02,"ip":"10.40.16.14","app":"3DSMax/1.0.0.0","args":"//depot/....3ds","startTime":"2017/12/07 15:00:21","endTime":"2017/12/07 15:00:23","running":1,"uCpu":10,"sCpu":11,"diskIn":12,"diskOut":13,"ipcIn":14,"ipcOut":15,"maxRss":4088,"pageFaults":22,"memMB":1,"memPeakMB":2,"cmdError":false,"tables":[]}`),
		cleanJSON(output[0]))
}

func TestNoStartRecord(t *testing.T) {
	testInput := `
Perforce server info:
	2020/01/11 02:00:02 pid 25396 p4sdp@chi 127.0.0.1 [p4/2019.2/LINUX26X86_64/1891638] 'user-serverid'
Perforce server info:
	2020/01/11 02:00:02 pid 25390 completed .008s 0+0us 0+8io 0+0net 7632k 0pf 
Perforce server info:
	2020/01/11 02:00:02 pid 25390 bot-integ@_____CLIENT_UNSET_____ 127.0.0.1/10.5.40.103 [jenkins.p4-plugin/1.10.3-SNAPSHOT/Linux (brokered)] 'user-login -s'
--- failed authentication check
--- lapse .008s
--- rpc msgs/size in+out 2+3/0mb+0mb himarks 795800/185540 snd/rcv .000s/.007s

Perforce server info:
	2020/01/11 02:00:02 pid 25396 completed .002s 0+0us 0+8io 0+0net 8036k 0pf 
Perforce server info:
	2020/01/11 02:00:02 pid 25396 p4sdp@chi 127.0.0.1 [p4/2019.2/LINUX26X86_64/1891638] 'user-serverid'
--- lapse .002s
--- rpc msgs/size in+out 2+3/0mb+0mb himarks 795800/795656 snd/rcv .000s/.000s
`
	output := parseLogLines(testInput)
	assert.Equal(t, 2, len(output))
	//assert.Equal(t, "", output[1])
	assert.JSONEq(t, cleanJSON(`{"processKey":"7c437167b3eef0a81ba6ecb710ad7572","cmd":"user-serverid","pid":25396,"lineNo":2,"user":"p4sdp","workspace":"chi","completedLapse":0.002,"ip":"127.0.0.1","app":"p4/2019.2/LINUX26X86_64/1891638","args":"","startTime":"2020/01/11 02:00:02","endTime":"2020/01/11 02:00:02","running":1,"diskOut":8,"maxRss":8036,"rpcMsgsIn":2,"rpcMsgsOut":3,"rpcHimarkFwd":795800,"rpcHimarkRev":795656,"cmdError":false,"tables":[]}`),
		cleanJSON(output[0]))
	assert.JSONEq(t, cleanJSON(`{"processKey":"9bbbb204208b1af212c38a906294708c","cmd":"user-login","pid":25390,"lineNo":4,"user":"bot-integ","workspace":"_____CLIENT_UNSET_____","completedLapse":0.008,"ip":"127.0.0.1/10.5.40.103","app":"jenkins.p4-plugin/1.10.3-SNAPSHOT/Linux (brokered)","args":"-s","startTime":"2020/01/11 02:00:02","endTime":"2020/01/11 02:00:02","running":1,"diskOut":8,"maxRss":7632,"rpcMsgsIn":2,"rpcMsgsOut":3,"rpcHimarkFwd":795800,"rpcHimarkRev":185540,"rpcRcv":0.007,"cmdError":false,"tables":[]}`),
		cleanJSON(output[1]))
}

func TestLogErrors(t *testing.T) {
	testInput := `
Perforce server info:
	2019/12/20 09:42:15 pid 25883 user1@ws1 10.1.3.158 [IntelliJ_IDEA_resolved/2018.1/LINUX26X86_64/1637071] 'user-resolved /home/user1/perforce_ws/ws1/.idea/... /home/user1/perforce_ws/ws1/...'

Perforce server error:
	Date 2019/12/20 09:42:15:
	Pid 25883
	Operation: user-resolved
	/home/user1/perforce_ws/ws1/... - no file(s) resolved.
`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	//assert.Equal(t, "", output[0])
	assert.JSONEq(t, cleanJSON(`{"processKey":"227e3b54b1283b1fef89bc5843eb87d5","cmd":"user-resolved","pid":25883,"lineNo":2,"user":"user1","workspace":"ws1","ip":"10.1.3.158","app":"IntelliJ_IDEA_resolved/2018.1/LINUX26X86_64/1637071","args":"/home/user1/perforce_ws/ws1/.idea/... /home/user1/perforce_ws/ws1/...","startTime":"2019/12/20 09:42:15","endTime":"0001/01/01 00:00:00","running":1,"cmdError":true,"tables":[]}`),
		cleanJSON(output[0]))
}

func TestIDLEErrors(t *testing.T) {
	testInput := `
Perforce server info:
	2020/01/11 02:01:01 pid 25601 swarm@~tmp.1578736802.31818.5e199ca2c9d493.85829556 10.5.70.45 [SWARM/2019.3-MAIN-TEST_ONLY/1897025] 'IDLE' exited unexpectedly, removed from monitor table.

Perforce server info:
	2020/01/11 02:04:01 pid 26617 git-fusion-user@git-fusion--gfprod3-8dd305d0-3459-11ea-a8b4-0050568421b4 10.5.40.30 [Git Fusion/2017.1.SNAPSHOT/1778910 (2019/04/01)/v82 (brokered)] 'IDLE' exited unexpectedly, removed from monitor table.
`
	output := parseLogLines(testInput)
	assert.Equal(t, 0, len(output))
}

func TestServerActiveThreads(t *testing.T) {
	testInput := `
Perforce server info:
	2020/01/11 02:00:02 pid 25396 p4sdp@chi 127.0.0.1 [p4/2019.2/LINUX26X86_64/1891638] 'user-serverid'
Perforce server info:
	2020/01/11 02:00:02 pid 25396 completed .008s 0+0us 0+8io 0+0net 7632k 0pf 
2020/01/11 02:00:05 731966731 pid 24961: Server is now using 148 active threads.
Perforce server info:
	2020/01/11 02:00:06 pid 6170 svc_wok@unknown background [p4d/2019.2/LINUX26X86_64/1891638] 'pull -i 1'
--- db.view
---   pages in+out+cached 2+3+96
---   locks read/write 4/5 rows get+pos+scan put+del 6+7+8 9+10
`
	output := parseLogLines(testInput)
	assert.Equal(t, 2, len(output))
	//assert.Equal(t, "", output[1])
	assert.JSONEq(t, cleanJSON(`{"processKey":"33ac9675a65f8c437998987e55c11f9f","cmd":"pull","pid":6170,"lineNo":7,"user":"svc_wok","workspace":"unknown","ip":"background","app":"p4d/2019.2/LINUX26X86_64/1891638","args":"-i 1","startTime":"2020/01/11 02:00:06","endTime":"2020/01/11 02:00:06","running":148,"cmdError":false,"tables":[{"tableName":"view","pagesIn":2,"pagesOut":3,"pagesCached":96,"readLocks":4,"writeLocks":5,"getRows":6,"posRows":7,"scanRows":8,"putRows":9,"delRows":10}]}`),
		cleanJSON(output[0]))
	assert.JSONEq(t, cleanJSON(`{"processKey":"7c437167b3eef0a81ba6ecb710ad7572","cmd":"user-serverid","pid":25396,"lineNo":2,"user":"p4sdp","workspace":"chi","completedLapse":0.008,"ip":"127.0.0.1","app":"p4/2019.2/LINUX26X86_64/1891638","args":"","startTime":"2020/01/11 02:00:02","endTime":"2020/01/11 02:00:02","running":1,"diskOut":8,"maxRss":7632,"cmdError":false,"tables":[]}`),
		cleanJSON(output[1]))
}

func TestDuplicatePulls(t *testing.T) {
	testInput := `
Perforce server info:
	2019/12/20 08:00:03 pid 6170 svc_wok@unknown background [p4d/2019.2/LINUX26X86_64/1891638] 'pull -i 1'
--- db.view
---   pages in+out+cached 2+3+96
---   locks read/write 4/5 rows get+pos+scan put+del 6+7+8 9+10
--- replica/pull(W)
---   total lock wait+held read/write 0ms+0ms/0ms+-25ms

Perforce server info:
	2019/12/20 08:00:03 pid 6170 svc_wok@unknown background [p4d/2019.2/LINUX26X86_64/1891638] 'pull -i 1'
--- db.domain
---   pages in+out+cached 2+3+96
---   locks read/write 0/1 rows get+pos+scan put+del 0+0+0 1+0
--- replica/pull(W)
---   total lock wait+held read/write 0ms+0ms/0ms+-25ms

Perforce server info:
	2019/12/20 08:00:03 pid 6170 svc_wok@unknown background [p4d/2019.2/LINUX26X86_64/1891638] 'pull -i 1'
--- db.domain
---   pages in+out+cached 2+3+96
---   locks read/write 0/1 rows get+pos+scan put+del 0+0+0 0+1
--- db.view
---   pages in+out+cached 2+3+96
---   locks read/write 0/1 rows get+pos+scan put+del 0+0+0 0+1
--- replica/pull(W)
---   total lock wait+held read/write 0ms+0ms/0ms+-25ms
`
	output := parseLogLines(testInput)
	assert.Equal(t, 3, len(output))
	//assert.Equal(t, "", output[2])
	assert.JSONEq(t, cleanJSON(`{"processKey":"642f3b3976afda703fb97524581913b7","cmd":"pull","pid":6170,"lineNo":2,"user":"svc_wok","workspace":"unknown","ip":"background","app":"p4d/2019.2/LINUX26X86_64/1891638","args":"-i 1","startTime":"2019/12/20 08:00:03","endTime":"2019/12/20 08:00:03","cmdError":false,"tables":[{"tableName":"view","pagesIn":2,"pagesOut":3,"pagesCached":96,"readLocks":4,"writeLocks":5,"getRows":6,"posRows":7,"scanRows":8,"putRows":9,"delRows":10}]}`),
		cleanJSON(output[0]))
	assert.JSONEq(t, cleanJSON(`{"processKey":"642f3b3976afda703fb97524581913b7.10","cmd":"pull","pid":6170,"lineNo":10,"user":"svc_wok","workspace":"unknown","ip":"background","app":"p4d/2019.2/LINUX26X86_64/1891638","args":"-i 1","startTime":"2019/12/20 08:00:03","endTime":"2019/12/20 08:00:03","cmdError":false,"tables":[{"tableName":"domain","pagesIn":2,"pagesOut":3,"pagesCached":96,"writeLocks":1,"putRows":1}]}`),
		cleanJSON(output[1]))
	assert.JSONEq(t, cleanJSON(`{"processKey":"642f3b3976afda703fb97524581913b7.18","cmd":"pull","pid":6170,"lineNo":18,"user":"svc_wok","workspace":"unknown","ip":"background","app":"p4d/2019.2/LINUX26X86_64/1891638","args":"-i 1","startTime":"2019/12/20 08:00:03","endTime":"2019/12/20 08:00:03","cmdError":false,"tables":[{"tableName":"domain","pagesIn":2,"pagesOut":3,"pagesCached":96,"writeLocks":1,"delRows":1},{"tableName":"view","pagesIn":2,"pagesOut":3,"pagesCached":96,"writeLocks":1,"delRows":1}]}`),
		cleanJSON(output[2]))
}

// Process multiple meta/db entries and intermediate
// This occurs when you run a sync with multiple arguments. Intermediate records are output for
// every argument and include "compute end" and "meta/db" records. They need to be treated
// as updates to the single sync command. Could probably even be ignored as the final one will
// contain the final results.
// In any case, it is important that they are not treated as multiple individual sync commands!
func TestSyncMultiArgMetaDb(t *testing.T) {
	testInput := `
Perforce server info:
	2017/12/07 15:00:01 pid 145941 builder@LON 10.10.16.171/10.10.20.195 [AutoWorker/1.0.0.0] 'user-sync //assets/level/instances.xml'

Perforce server info:
2017/12/07 15:00:01 pid 145941 builder@LON 10.10.16.171/10.10.20.195 [AutoWorker/1.0.0.0] 'user-sync //assets/level/instances.xml'
--- meta/db(R)
---   total lock wait+held read/write 0ms+0ms/0ms+0ms

Perforce server info:
	2017/12/07 15:00:01 pid 145941 compute end .007s 3+1us 16+112io 0+0net 4452k 0pf 
Perforce server info:
	Server network estimates: files added/updated/deleted=0/0/0, bytes added/updated=0/0
Perforce server info:
	2017/12/07 15:00:01 pid 145941 builder@LON 10.10.16.171/10.10.20.195 [AutoWorker/1.0.0.0] 'user-sync //assets/level/instances.xml'
--- meta/db(R)
---   total lock wait+held read/write 0ms+0ms/0ms+0ms

Perforce server info:
	2017/12/07 15:00:01 pid 145941 compute end .007s 3+1us 16+128io 0+0net 4452k 0pf 
Perforce server info:
	Server network estimates: files added/updated/deleted=0/0/0, bytes added/updated=0/0
Perforce server info:
	2017/12/07 15:00:01 pid 145941 builder@LON 10.10.16.171/10.10.20.195 [AutoWorker/1.0.0.0] 'user-sync //assets/level/instances.xml'
--- meta/db(R)
---   total lock wait+held read/write 0ms+0ms/0ms+0ms

Perforce server info:
	2017/12/07 15:00:01 pid 145941 compute end .008s 4+1us 16+144io 0+0net 4452k 0pf 
Perforce server info:
	Server network estimates: files added/updated/deleted=0/0/0, bytes added/updated=0/0
Perforce server info:
	2017/12/07 15:00:01 pid 145941 builder@LON 10.10.16.171/10.10.20.195 [AutoWorker/1.0.0.0] 'user-sync //assets/level/instances.xml'
--- meta/db(R)
---   total lock wait+held read/write 0ms+0ms/0ms+0ms

Perforce server info:
	2017/12/07 15:00:01 pid 145941 compute end .008s 4+1us 16+160io 0+0net 4452k 0pf 
Perforce server info:
	Server network estimates: files added/updated/deleted=0/0/0, bytes added/updated=0/0
Perforce server info:
--- meta/db(R)
---   total lock wait+held read/write 0ms+0ms/0ms+0ms

Perforce server info:
	2017/12/07 15:00:01 pid 145941 compute end .110s 77+25us 112+3120io 0+0net 4964k 0pf
Perforce server info:
	Server network estimates: files added/updated/deleted=0/0/0, bytes added/updated=0/0
Perforce server info:
	2017/12/07 15:00:01 pid 145941 completed .111s 77+25us 112+3136io 0+0net 4964k 0pf
`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	//assert.Equal(t, "", output[0])
	assert.JSONEq(t, cleanJSON(`{"processKey":"026c2d4135085764d23fd21f41d30f77","cmd":"user-sync","pid":145941,"lineNo":2,"user":"builder","workspace":"LON","computeLapse":0.11,"completedLapse":0.111,"ip":"10.10.16.171/10.10.20.195","app":"AutoWorker/1.0.0.0","args":"//assets/level/instances.xml","startTime":"2017/12/07 15:00:01","endTime":"2017/12/07 15:00:01","running":1,"uCpu":77,"sCpu":25,"diskIn":112,"diskOut":3136,"maxRss":4964,"cmdError":false,"tables":[]}`),
		cleanJSON(output[0]))
}

func TestEdgeLog(t *testing.T) {
	testInput := `
Perforce server info:
	2018/06/01 04:29:43 pid 55997 svc0@unknown background [p4d/2018.1/DARWIN90X86_64/1660568] 'pull -I 100 -b 1'
--- db.counters
---   pages in+out+cached 2+0+2
---   locks read/write 0/1 rows get+pos+scan put+del 1+0+0 0+0
--- replica/pull(W)
---   total lock wait+held read/write 0ms+0ms/0ms+1ms

Perforce server info:
	2018/06/01 04:29:43 pid 55997 svc0@unknown background [p4d/2018.1/DARWIN90X86_64/1660568] 'pull -I 100 -b 1'
--- db.counters
---   pages in+out+cached 4+3+2
---   locks read/write 0/2 rows get+pos+scan put+del 0+0+0 1+1
--- replica/pull(W)
---   total lock wait+held read/write 0ms+0ms/0ms+1ms

Perforce server info:
	2018/06/01 04:29:43 pid 55997 svc0@unknown background [p4d/2018.1/DARWIN90X86_64/1660568] 'pull -I 100 -b 1'
--- lapse .001s
--- db.counters
---   pages in+out+cached 2+3+2
---   locks read/write 0/1 rows get+pos+scan put+del 1+0+0 1+0
--- db.change
---   pages in+out+cached 4+3+2
---   locks read/write 0/1 rows get+pos+scan put+del 0+0+0 1+0
--- db.changex
---   pages in+out+cached 4+3+2
---   locks read/write 0/1 rows get+pos+scan put+del 0+0+0 1+0
--- db.desc
---   pages in+out+cached 4+3+2
---   locks read/write 0/1 rows get+pos+scan put+del 0+0+0 1+0
--- replica/pull(W)
---   total lock wait+held read/write 0ms+0ms/0ms+0ms

Pull command 55998 xfering //depot/some_file#1.1 (add, text)
	2018/06/01 04:29:44 544730000 pid 55998: connected to central server
Perforce server info:
	2018/06/01 04:29:44 pid 55998 svc0@unknown background [p4d/2018.1/DARWIN90X86_64/1660568] 'pull -u -i 1 -b 1'
--- rdb.lbr
---   pages in+out+cached 7+4+2
---   locks read/write 0/3 rows get+pos+scan put+del 1+1+4 1+1
`
	output := parseLogLines(testInput)
	assert.Equal(t, 4, len(output))
	//assert.Equal(t, "", output[3])
	assert.JSONEq(t, cleanJSON(`{"processKey":"44c92f3be809fd15dfc26cc8fb359216","cmd":"pull","pid":55998,"lineNo":38,"user":"svc0","workspace":"unknown","ip":"background","app":"p4d/2018.1/DARWIN90X86_64/1660568","args":"-u -i 1 -b 1","startTime":"2018/06/01 04:29:44","endTime":"2018/06/01 04:29:44","cmdError":false,"tables":[{"tableName":"rdb.lbr","pagesIn":7,"pagesOut":4,"pagesCached":2,"writeLocks":3,"getRows":1,"posRows":1,"scanRows":4,"putRows":1,"delRows":1}]}`),
		cleanJSON(output[0]))
	assert.JSONEq(t, cleanJSON(`{"processKey":"9e39beedee815db46bb4c870c11a0b8d","cmd":"pull","pid":55997,"lineNo":2,"user":"svc0","workspace":"unknown","ip":"background","app":"p4d/2018.1/DARWIN90X86_64/1660568","args":"-I 100 -b 1","startTime":"2018/06/01 04:29:43","endTime":"2018/06/01 04:29:43","cmdError":false,"tables":[{"tableName":"counters","pagesIn":2,"pagesCached":2,"writeLocks":1,"getRows":1}]}`),
		cleanJSON(output[1]))
	assert.JSONEq(t, cleanJSON(`{"processKey":"9e39beedee815db46bb4c870c11a0b8d.10","cmd":"pull","pid":55997,"lineNo":10,"user":"svc0","workspace":"unknown","ip":"background","app":"p4d/2018.1/DARWIN90X86_64/1660568","args":"-I 100 -b 1","startTime":"2018/06/01 04:29:43","endTime":"2018/06/01 04:29:43","cmdError":false,"tables":[{"tableName":"counters","pagesIn":4,"pagesOut":3,"pagesCached":2,"writeLocks":2,"putRows":1,"delRows":1}]}`),
		cleanJSON(output[2]))
	assert.JSONEq(t, cleanJSON(`{"processKey":"9e39beedee815db46bb4c870c11a0b8d.18","cmd":"pull","pid":55997,"lineNo":18,"user":"svc0","workspace":"unknown","completedLapse":0.001,"ip":"background","app":"p4d/2018.1/DARWIN90X86_64/1660568","args":"-I 100 -b 1","startTime":"2018/06/01 04:29:43","endTime":"2018/06/01 04:29:43","cmdError":false,"tables":[{"tableName":"change","pagesIn":4,"pagesOut":3,"pagesCached":2,"writeLocks":1,"putRows":1},{"tableName":"changex","pagesIn":4,"pagesOut":3,"pagesCached":2,"writeLocks":1,"putRows":1},{"tableName":"counters","pagesIn":2,"pagesOut":3,"pagesCached":2,"writeLocks":1,"getRows":1,"putRows":1},{"tableName":"desc","pagesIn":4,"pagesOut":3,"pagesCached":2,"writeLocks":1,"putRows":1}]}`),
		cleanJSON(output[3]))
}

func TestBlockWithLocksAcquired(t *testing.T) {
	testInput := `
Perforce server info:
	2018/09/06 06:00:02 pid 22245 auto@archive_auto 127.0.0.1 [archive/v60] 'user-revert /usr/local/arch/datastore/...'

Perforce server info:
	2018/09/06 06:00:02 pid 22245 completed 6.92s 6901+4us 32+8io 0+0net 19996k 0pf 

Perforce server info:
	2018/09/06 06:00:02 pid 22245 auto@archive_auto 127.0.0.1 [archive/v60] 'user-revert /usr/local/arch/datastore/...'
locks acquired by blocking after 3 non-blocking attempts
--- db.resolve
---   total lock wait+held read/write 23792ms+3ms/2ms+1ms
---   max lock wait+held read/write 23792ms+3ms/2ms+1ms
--- db.protect
---   total lock wait+held read/write 4ms+6875ms/5ms+6ms
--- clients/archive_ghostdir%2Etapioca%2Edata_ump_72%2E246%2E96%2E199(W)
---   total lock wait+held read/write 0ms+0ms/0ms+23800ms
`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	//assert.Equal(t, "", output[0])
	assert.JSONEq(t, cleanJSON(`{"processKey":"f7d483631e94d16adde6c5306be15fbe","cmd":"user-revert","pid":22245,"lineNo":2,"user":"auto","workspace":"archive_auto","completedLapse":6.92,"ip":"127.0.0.1","app":"archive/v60","args":"/usr/local/arch/datastore/...","startTime":"2018/09/06 06:00:02","endTime":"2018/09/06 06:00:02","running":1,"uCpu":6901,"sCpu":4,"diskIn":32,"diskOut":8,"maxRss":19996,"cmdError":false,"tables":[{"tableName":"protect","totalReadWait":4,"totalReadHeld":6875,"totalWriteWait":5,"totalWriteHeld":6},{"tableName":"resolve","totalReadWait":23792,"totalReadHeld":3,"totalWriteWait":2,"totalWriteHeld":1,"maxReadWait":23792,"maxReadHeld":3,"maxWriteWait":2,"maxWriteHeld":1}]}`),
		cleanJSON(output[0]))
	assert.JSONEq(t, cleanJSON(`{"processKey":"f7d483631e94d16adde6c5306be15fbe","cmd":"user-revert","pid":22245,"lineNo":2,"user":"auto","workspace":"archive_auto","completedLapse":6.92,"ip":"127.0.0.1","app":"archive/v60","args":"/usr/local/arch/datastore/...","startTime":"2018/09/06 06:00:02","endTime":"2018/09/06 06:00:02","running":1,"uCpu":6901,"sCpu":4,"diskIn":32,"diskOut":8,"maxRss":19996,"cmdError":false,"tables":[{"tableName":"protect","totalReadWait":4,"totalReadHeld":6875,"totalWriteWait":5,"totalWriteHeld":6},{"tableName":"resolve","totalReadWait":23792,"totalReadHeld":3,"totalWriteWait":2,"totalWriteHeld":1,"maxReadWait":23792,"maxReadHeld":3,"maxWriteWait":2,"maxWriteHeld":1}]}`),
		cleanJSON(output[0]))
}

func TestTriggers(t *testing.T) {
	testInput := `
Perforce server info:
	2020/03/11 06:08:16 pid 15855 fred@fred_ws 10.1.4.213/10.1.3.243 [Helix P4V/NTX64/2019.2/1904275/v86] 'user-change -i'
Perforce server info:
	2020/03/11 06:08:16 pid 17916 svc_p4d_ha_chi@unknown 10.5.70.41 [p4d/2019.2/LINUX26X86_64/1908095] 'rmt-Journal'
--- lapse .202s
--- rpc msgs/size in+out 0+1/0mb+0mb himarks 280100/278660 snd/rcv .000s/.000s
--- db.counters
---   pages in+out+cached 6+0+2
---   locks read/write 6/0 rows get+pos+scan put+del 6+0+0 0+0

Perforce server info:
	2020/03/11 06:08:16 pid 17916 svc_p4d_ha_chi@unknown 10.5.70.41 [p4d/2019.2/LINUX26X86_64/1908095] 'rmt-Journal'
--- lapse .001s
--- rpc msgs/size in+out 0+1/0mb+0mb himarks 280100/278660 snd/rcv .000s/.000s
--- db.counters
---   pages in+out+cached 1+0+2
---   locks read/write 1/0 rows get+pos+scan put+del 1+0+0 0+0

Perforce server info:
	2020/03/11 06:08:16 pid 15855 fred@fred_ws 10.1.4.213/10.1.3.243 [Helix P4V/NTX64/2019.2/1904275/v86] 'user-change -i' trigger swarm.changesave
lapse .076s
Perforce server info:
	2020/03/11 06:08:16 pid 15855 fred@fred_ws 10.1.4.213/10.1.3.243 [Helix P4V/NTX64/2019.2/1904275/v86] 'user-change -i'
--- storageup/storageup(R)
---   total lock wait+held read/write 1ms+2ms/3ms+4ms

Perforce server info:
	2020/03/11 06:08:16 pid 15855 fred@fred_ws 10.1.4.213/10.1.3.243 [Helix P4V/NTX64/2019.2/1904275/v86] 'user-change -i'
--- storageup/storagemasterup(R)
---   total lock wait+held read/write 1ms+2ms/3ms+4ms

Perforce server info:
	2020/03/11 06:08:17 pid 15855 completed .276s 4+4us 256+224io 0+0net 9212k 0pf 
Perforce server info:
	2020/03/11 06:08:16 pid 15855 fred@fred_ws 10.1.4.213/10.1.3.243 [Helix P4V/NTX64/2019.2/1904275/v86] 'user-change -i'
--- lapse .276s
--- usage 4+4us 256+240io 0+0net 9212k 0pf 
--- rpc msgs/size in+out 3+5/0mb+0mb himarks 280100/280100 snd/rcv .000s/.190s
--- db.counters
---   pages in+out+cached 7+6+2
---   locks read/write 1/2 rows get+pos+scan put+del 3+0+0 2+0
--- db.protect
---   pages in+out+cached 9+0+7
---   locks read/write 1/0 rows get+pos+scan put+del 0+1+345 0+0
---   peek count 1 wait+held total/max 0ms+0ms/0ms+0ms
--- db.monitor
---   pages in+out+cached 2+4+256
---   locks read/write 0/2 rows get+pos+scan put+del 0+0+0 2+0
--- clients/fred_ws(W)
---   total lock wait+held read/write 0ms+0ms/0ms+181ms
`
	output := parseLogLines(testInput)
	assert.Equal(t, 3, len(output))
	//assert.Equal(t, "", output[2])
	assert.JSONEq(t, cleanJSON(`{"processKey":"b9ec8da8ea642419a06f8ac4060f261c","cmd":"rmt-Journal","pid":17916,"lineNo":4,"user":"svc_p4d_ha_chi","workspace":"unknown","completedLapse":0.202,"ip":"10.5.70.41","app":"p4d/2019.2/LINUX26X86_64/1908095","args":"","startTime":"2020/03/11 06:08:16","endTime":"2020/03/11 06:08:16","running":1,"rpcMsgsOut":1,"rpcHimarkFwd":280100,"rpcHimarkRev":278660,"cmdError":false,"tables":[{"tableName":"counters","pagesIn":6,"pagesCached":2,"readLocks":6,"getRows":6}]}`),
		cleanJSON(output[0]))
	assert.JSONEq(t, cleanJSON(`{"processKey":"b9ec8da8ea642419a06f8ac4060f261c.12","cmd":"rmt-Journal","pid":17916,"lineNo":12,"user":"svc_p4d_ha_chi","workspace":"unknown","completedLapse":0.001,"ip":"10.5.70.41","app":"p4d/2019.2/LINUX26X86_64/1908095","args":"","startTime":"2020/03/11 06:08:16","endTime":"2020/03/11 06:08:16","running":1,"rpcMsgsOut":1,"rpcHimarkFwd":280100,"rpcHimarkRev":278660,"cmdError":false,"tables":[{"tableName":"counters","pagesIn":1,"pagesCached":2,"readLocks":1,"getRows":1}]}`),
		cleanJSON(output[1]))
	assert.JSONEq(t, cleanJSON(`{"processKey":"b9f9aee10027df004a0e35a3c9931e27","cmd":"user-change","pid":15855,"lineNo":2,"user":"fred","workspace":"fred_ws","completedLapse":0.276,"ip":"10.1.4.213/10.1.3.243","app":"Helix P4V/NTX64/2019.2/1904275/v86","args":"-i","startTime":"2020/03/11 06:08:16","endTime":"2020/03/11 06:08:17","running":1,"uCpu":4,"sCpu":4,"diskIn":256,"diskOut":240,"maxRss":9212,"rpcMsgsIn":3,"rpcMsgsOut":5,"rpcHimarkFwd":280100,"rpcHimarkRev":280100,"rpcRcv":0.19,"cmdError":false,"tables":[{"tableName":"counters","pagesIn":7,"pagesOut":6,"pagesCached":2,"readLocks":1,"writeLocks":2,"getRows":3,"putRows":2},{"tableName":"monitor","pagesIn":2,"pagesOut":4,"pagesCached":256,"writeLocks":2,"putRows":2},{"tableName":"protect","pagesIn":9,"pagesCached":7,"readLocks":1,"posRows":1,"scanRows":345,"peekCount":1},{"tableName":"storagemasterup_R","totalReadWait":1,"totalReadHeld":2,"totalWriteWait":3,"totalWriteHeld":4},{"tableName":"storageup_R","totalReadWait":1,"totalReadHeld":2,"totalWriteWait":3,"totalWriteHeld":4},{"tableName":"trigger_swarm.changesave","triggerLapse":0.076}]}`),
		cleanJSON(output[2]))
}

func TestTriggersCommit(t *testing.T) {
	testInput := `
Perforce server info:
	2020/07/20 15:00:13 pid 59469 robomerge@ROBOMERGE_EOSSDK_EOSSDK_Dev_EAC 10.1.20.80 [robomerge/v717] 'dm-CommitSubmit' trigger swarm.commit
lapse .079s
`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	//assert.Equal(t, "", output[0])
	assert.JSONEq(t, cleanJSON(`{"processKey":"940a4da8bf0e516fdd8685452d489537","cmd":"dm-CommitSubmit","pid":59469,"lineNo":2,"user":"robomerge","workspace":"ROBOMERGE_EOSSDK_EOSSDK_Dev_EAC","ip":"10.1.20.80","app":"robomerge/v717","args":"","startTime":"2020/07/20 15:00:13","endTime":"0001/01/01 00:00:00","running":1,"cmdError":false,"tables":[{"tableName":"trigger_swarm.commit","triggerLapse":0.079}]}`),
		cleanJSON(output[0]))
}

func TestTriggersStrict(t *testing.T) {
	testInput := `
Perforce server info:
	2020/07/20 15:00:13 pid 59469 robomerge@ROBOMERGE_EOSSDK_EOSSDK_Dev_EAC 10.1.20.80 [robomerge/v717] 'dm-CommitSubmit' trigger swarm.strict
lapse 1.39s
`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	//assert.Equal(t, "", output[0])
	assert.JSONEq(t, cleanJSON(`{"processKey":"940a4da8bf0e516fdd8685452d489537","cmd":"dm-CommitSubmit","pid":59469,"lineNo":2,"user":"robomerge","workspace":"ROBOMERGE_EOSSDK_EOSSDK_Dev_EAC","ip":"10.1.20.80","app":"robomerge/v717","args":"","startTime":"2020/07/20 15:00:13","endTime":"0001/01/01 00:00:00","running":1,"cmdError":false,"tables":[{"tableName":"trigger_swarm.strict","triggerLapse":1.39}]}`),
		cleanJSON(output[0]))
}

func TestForLbrRcs(t *testing.T) {
	testInput := `
Perforce server info:
	2017/12/07 15:00:21 pid 148469 fred@LONWS 10.40.16.14 [3DSMax/1.0.0.0] 'user-files //depot/....3ds'
Perforce server info:
	2017/12/07 15:00:23 pid 148469 completed 2.01s 7+4us 0+584io 0+0net 4580k 0pf
Perforce server info:
	2017/12/07 15:00:21 pid 148469 fred@LONWS 10.40.16.14 [3DSMax/1.0.0.0] 'user-files //depot/....3ds'
--- lapse 2.02s
--- usage 10+11us 12+13io 14+15net 4088k 22pf
--- lbr Rcs
---   opens+closes+checkins+exists 1+0+0+4
---   reads+readbytes+writes+writebytes 6+12.1K+0+3.3K
`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	//assert.Equal(t, "", output[0])
	assert.JSONEq(t, cleanJSON(`{"processKey":"f00da0667f738b28e706360f6997741e","cmd":"user-files","pid":148469,"lineNo":2,"user":"fred","workspace":"LONWS","completedLapse":2.02,"ip":"10.40.16.14","app":"3DSMax/1.0.0.0","args":"//depot/....3ds","startTime":"2017/12/07 15:00:21","endTime":"2017/12/07 15:00:23","running":1,"uCpu":10,"sCpu":11,"diskIn":12,"diskOut":13,"ipcIn":14,"ipcOut":15,"maxRss":4088,"pageFaults":22,"lbrRcsOpens":1,"lbrRcsExists":4,"lbrRcsReads":6,"lbrRcsReadBytes":12390,"lbrRcsWriteBytes":3379,"cmdError":false,"tables":[]}`),
		cleanJSON(output[0]))
}

func TestForCompress(t *testing.T) {
	testInput := `
Perforce server info:
	2017/12/07 15:00:21 pid 148469 fred@LONWS 10.40.16.14 [3DSMax/1.0.0.0] 'user-files //depot/....3ds'
Perforce server info:
	2017/12/07 15:00:23 pid 148469 completed 2.01s 7+4us 0+584io 0+0net 4580k 0pf
Perforce server info:
	2017/12/07 15:00:21 pid 148469 fred@LONWS 10.40.16.14 [3DSMax/1.0.0.0] 'user-files //depot/....3ds'
--- lapse 2.02s
--- usage 10+11us 12+13io 14+15net 4088k 22pf
--- lbr Compress
---   opens+closes+checkins+exists 6+4+2+5
---   reads+readbytes+writes+writebytes 3+12.1P+0+0
`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	//assert.Equal(t, "", output[0])
	assert.JSONEq(t, cleanJSON(`{"processKey":"f00da0667f738b28e706360f6997741e","cmd":"user-files","pid":148469,"lineNo":2,"user":"fred","workspace":"LONWS","completedLapse":2.02,"ip":"10.40.16.14","app":"3DSMax/1.0.0.0","args":"//depot/....3ds","startTime":"2017/12/07 15:00:21","endTime":"2017/12/07 15:00:23","running":1,"uCpu":10,"sCpu":11,"diskIn":12,"diskOut":13,"ipcIn":14,"ipcOut":15,"maxRss":4088,"pageFaults":22,"lbrCompressOpens":6,"lbrCompressCloses":4,"lbrCompressCheckins":2,"lbrCompressExists":5,"lbrCompressReads":3,"lbrCompressReadBytes":13623389302292480,"cmdError":false,"tables":[]}`),
		cleanJSON(output[0]))
}

func TestForUnCompress(t *testing.T) {
	testInput := `
Perforce server info:
	2017/12/07 15:00:21 pid 148469 fred@LONWS 10.40.16.14 [3DSMax/1.0.0.0] 'user-files //depot/....3ds'
Perforce server info:
	2017/12/07 15:00:23 pid 148469 completed 2.01s 7+4us 0+584io 0+0net 4580k 0pf
Perforce server info:
	2017/12/07 15:00:21 pid 148469 fred@LONWS 10.40.16.14 [3DSMax/1.0.0.0] 'user-files //depot/....3ds'
--- lapse 2.02s
--- usage 10+11us 12+13io 14+15net 4088k 22pf
--- lbr Uncompress
---   opens+closes+checkins+exists 1+2+3+4
---   reads+readbytes+writes+writebytes 6+0+0+4.1K
`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	//assert.Equal(t, "", output[0])
	assert.JSONEq(t, cleanJSON(`{"processKey":"f00da0667f738b28e706360f6997741e","cmd":"user-files","pid":148469,"lineNo":2,"user":"fred","workspace":"LONWS","completedLapse":2.02,"ip":"10.40.16.14","app":"3DSMax/1.0.0.0","args":"//depot/....3ds","startTime":"2017/12/07 15:00:21","endTime":"2017/12/07 15:00:23","running":1,"uCpu":10,"sCpu":11,"diskIn":12,"diskOut":13,"ipcIn":14,"ipcOut":15,"maxRss":4088,"pageFaults":22,"lbrUncompressOpens":1,"lbrUncompressCloses":2,"lbrUncompressCheckins":3,"lbrUncompressExists":4,"lbrUncompressReads":6,"lbrUncompressWriteBytes":4198,"cmdError":false,"tables":[]}`),
		cleanJSON(output[0]))
}

func TestForLbrAndTable(t *testing.T) {
	testInput := `
Perforce server info:
	2023/07/01 02:00:02 pid 1871637 build@cmdr-tools-change-155476395 127.0.0.1/10.5.64.108 [p4/2018.1/LINUX26X86_64/1957529 (brokered)] 'user-transmit -t1871630 -b8 -s524288 -p'

Perforce server info:
	2023/07/01 02:00:02 pid 1871637 completed .011s 5+4us 0+0io 0+0net 10364k 0pf

Perforce server info:
	2023/07/01 02:00:02 pid 1871637 build@cmdr-tools-change-155476395 127.0.0.1/10.5.64.108 [p4/2018.1/LINUX26X86_64/1957529 (brokered)] 'user-transmit -t1871630 -b8 -s524288 -p'
--- lapse .011s
--- usage 5+4us 0+8io 0+0net 10364k 0pf
--- memory cmd/proc 25mb/26mb
--- rpc msgs/size in+out 2+74/0mb+0mb himarks 97604/318788 snd/rcv .000s/.001s
--- db.topology
---   pages in+out+cached 5+0+4
---   locks read/write 1/0 rows get+pos+scan put+del 0+1+1 0+0
--- db.monitor
---   pages in+out+cached 2+4+4096
---   locks read/write 0/2 rows get+pos+scan put+del 0+0+0 2+0
---   total lock wait+held read/write 0ms+0ms/1ms+0ms
---   max lock wait+held read/write 0ms+0ms/1ms+0ms
--- lbr Rcs
---   opens+closes+checkins+exists 8+8+0+0
---   reads+readbytes+writes+writebytes 16+197.8K+0+0
---   digests+filesizes+modtimes+copies 1+2+3+4
--- lbr Compress
---   opens+closes+checkins+exists 16+16+0+0
---   reads+readbytes+writes+writebytes 32+138.7K+0+0
`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	//assert.Equal(t, "", output[0])
	assert.JSONEq(t, cleanJSON(`{"processKey":"c64b38c5e71582bd477ffcaab5b3514d","cmd":"user-transmit","pid":1871637,"lineNo":2,"user":"build","workspace":"cmdr-tools-change-155476395","completedLapse":0.011,"ip":"127.0.0.1/10.5.64.108","app":"p4/2018.1/LINUX26X86_64/1957529 (brokered)","args":"-t1871630 -b8 -s524288 -p","startTime":"2023/07/01 02:00:02","endTime":"2023/07/01 02:00:02","running":1,"uCpu":5,"sCpu":4,"diskOut":8,"maxRss":10364,"memMB":25,"memPeakMB":26,"rpcMsgsIn":2,"rpcMsgsOut":74,"rpcHimarkFwd":97604,"rpcHimarkRev":318788,"rpcRcv":0.001,"lbrRcsOpens":8,"lbrRcsCloses":8,"lbrRcsReads":16,"lbrRcsReadBytes":202547,"lbrRcsDigests":1,"lbrRcsFileSizes":2,"lbrRcsModTimes":3,"lbrRcsCopies":4,"lbrCompressOpens":16,"lbrCompressCloses":16,"lbrCompressReads":32,"lbrCompressReadBytes":142028,"cmdError":false,"tables":[{"tableName":"monitor","pagesIn":2,"pagesOut":4,"pagesCached":4096,"writeLocks":2,"putRows":2,"totalWriteWait":1,"maxWriteWait":1},{"tableName":"topology","pagesIn":5,"pagesCached":4,"readLocks":1,"posRows":1,"scanRows":1}]}`),
		cleanJSON(output[0]))
}

func TestForLbrUncompressDigestsFilesize(t *testing.T) {
	testInput := `
	Perforce server info:
	2017/12/07 15:00:21 pid 148469 fred@LONWS 10.40.16.14 [3DSMax/1.0.0.0] 'user-files //depot/....3ds'
Perforce server info:
	2017/12/07 15:00:23 pid 148469 completed 2.01s 7+4us 0+584io 0+0net 4580k 0pf
Perforce server info:
	2017/12/07 15:00:21 pid 148469 fred@LONWS 10.40.16.14 [3DSMax/1.0.0.0] 'user-files //depot/....3ds'
--- lapse 2.02s
--- usage 10+11us 12+13io 14+15net 4088k 22pf
--- lbr Uncompress
---   opens+closes+checkins+exists 1+2+3+4
---   reads+readbytes+writes+writebytes 6+0+0+4.1K
---   digests+filesizes+modtimes+copies 3+4+5+6
`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	//assert.Equal(t, "", output[0])
	assert.JSONEq(t, cleanJSON(`{"processKey":"f00da0667f738b28e706360f6997741e","cmd":"user-files","pid":148469,"lineNo":4,"user":"fred","workspace":"LONWS","completedLapse":2.02,"ip":"10.40.16.14","app":"3DSMax/1.0.0.0","args":"//depot/....3ds","startTime":"2017/12/07 15:00:21","endTime":"2017/12/07 15:00:23","uCpu":10,"sCpu":11,"diskIn":12,"diskOut":13,"ipcIn":14,"ipcOut":15,"maxRss":4088,"pageFaults":22,"lbrUncompressOpens":1,"lbrUncompressCloses":2,"lbrUncompressCheckins":3,"lbrUncompressExists":4,"lbrUncompressReads":6,"lbrUncompressWriteBytes":4198,"lbrUncompressDigests":3,"lbrUncompressFileSizes":4,"lbrUncompressModTimes":5,"lbrUncompressCopies":6,"cmdError":false,"tables":[]}`),
		cleanJSON(output[0]))
}

func TestForLbrCompressDigestsFilesize(t *testing.T) {
	testInput := `
	Perforce server info:
	2017/12/07 15:00:21 pid 148469 fred@LONWS 10.40.16.14 [3DSMax/1.0.0.0] 'user-files //depot/....3ds'
Perforce server info:
	2017/12/07 15:00:23 pid 148469 completed 2.01s 7+4us 0+584io 0+0net 4580k 0pf
Perforce server info:
	2017/12/07 15:00:21 pid 148469 fred@LONWS 10.40.16.14 [3DSMax/1.0.0.0] 'user-files //depot/....3ds'
--- lapse 2.02s
--- usage 10+11us 12+13io 14+15net 4088k 22pf
--- lbr Compress
---   opens+closes+checkins+exists 4+5+6+7
---   reads+readbytes+writes+writebytes 6+0+0+4.1K
---   digests+filesizes+modtimes+copies 21+22+23+24
`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	//assert.Equal(t, "", output[0])
	assert.JSONEq(t, cleanJSON(`{"processKey":"f00da0667f738b28e706360f6997741e","cmd":"user-files","pid":148469,"lineNo":4,"user":"fred","workspace":"LONWS","completedLapse":2.02,"ip":"10.40.16.14","app":"3DSMax/1.0.0.0","args":"//depot/....3ds","startTime":"2017/12/07 15:00:21","endTime":"2017/12/07 15:00:23","uCpu":10,"sCpu":11,"diskIn":12,"diskOut":13,"ipcIn":14,"ipcOut":15,"maxRss":4088,"pageFaults":22,"lbrCompressOpens":4,"lbrCompressCloses":5,"lbrCompressCheckins":6,"lbrCompressExists":7,"lbrCompressReads":6,"lbrCompressWriteBytes":4198,"lbrCompressDigests":21,"lbrCompressFileSizes":22,"lbrCompressModTimes":23,"lbrCompressCopies":24,"cmdError":false,"tables":[]}`),
		cleanJSON(output[0]))
}

func TestForLbrDigestsFilesize(t *testing.T) {
	testInput := `
	Perforce server info:
	2017/12/07 15:00:21 pid 148469 fred@LONWS 10.40.16.14 [3DSMax/1.0.0.0] 'user-files //depot/....3ds'
Perforce server info:
	2017/12/07 15:00:23 pid 148469 completed 2.01s 7+4us 0+584io 0+0net 4580k 0pf
Perforce server info:
	2017/12/07 15:00:21 pid 148469 fred@LONWS 10.40.16.14 [3DSMax/1.0.0.0] 'user-files //depot/....3ds'
--- lapse 2.02s
--- usage 10+11us 12+13io 14+15net 4088k 22pf
--- lbr Compress
---   digests+filesizes+modtimes+copies 1+2+3+4
`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	//assert.Equal(t, "", output[0])
	assert.JSONEq(t, cleanJSON(`{"processKey":"f00da0667f738b28e706360f6997741e","cmd":"user-files","pid":148469,"lineNo":4,"user":"fred","workspace":"LONWS","completedLapse":2.02,"ip":"10.40.16.14","app":"3DSMax/1.0.0.0","args":"//depot/....3ds","startTime":"2017/12/07 15:00:21","endTime":"2017/12/07 15:00:23","uCpu":10,"sCpu":11,"diskIn":12,"diskOut":13,"ipcIn":14,"ipcOut":15,"maxRss":4088,"pageFaults":22,"lbrCompressDigests":1,"lbrCompressFileSizes":2,"lbrCompressModTimes":3,"lbrCompressCopies":4,"cmdError":false,"tables":[]}`),
		cleanJSON(output[0]))
}

func TestLbrRegex(t *testing.T) {
	tests := []lbrRegex{{result: true, line: "---   reads+readbytes+writes+writebytes 0+0+0+0"},
		{result: true, line: "---   reads+readbytes+writes+writebytes 1+2.8G+3+4.5T"},
		{result: true, line: "---   reads+readbytes+writes+writebytes 1+2.8G+3+0"},
		{result: true, line: "---   reads+readbytes+writes+writebytes 1+0+3+1.3T"},
	}
	for _, r := range tests {
		assert.Equal(t, r.result, reTrackLbrReadWrite.MatchString(r.line))
	}
	m := reTrackLbrReadWrite.FindStringSubmatch("---   reads+readbytes+writes+writebytes 1+0+3+1.3T")
	assert.Equal(t, "1", m[1])
	assert.Equal(t, "0", m[2])
	assert.Equal(t, "3", m[3])
	assert.Equal(t, "1.3T", m[4])

	m = reTrackLbrReadWrite.FindStringSubmatch("---   reads+readbytes+writes+writebytes 1+2.1P+3+1.4G")
	assert.Equal(t, "1", m[1])
	assert.Equal(t, "2.1P", m[2])
	assert.Equal(t, "3", m[3])
	assert.Equal(t, "1.4G", m[4])

	m = reTrackLbrReadWrite.FindStringSubmatch("---   reads+readbytes+writes+writebytes 1+6.2K+3+0")
	assert.Equal(t, "1", m[1])
	assert.Equal(t, "6.2K", m[2])
	assert.Equal(t, "3", m[3])
	assert.Equal(t, "0", m[4])

}

func TestMultiComputes(t *testing.T) {
	testInput := `
Perforce server info:
	2024/04/03 12:20:14 pid 5032 fred@fred-Dinner-dev 10.1.2.212 [UnrealGameSync/v84] 'user-changes -m1 -ssubmitted //fred-Dinner-dev/*.cs@<=764311 //fred-Dinner-dev/Engine/....cs@<=764311 //fred-Dinner-dev/Dinner/....cs@<=764311'
Perforce server info:
	2024/04/03 12:20:14 pid 5032 compute end .000s
Perforce server info:
	2024/04/03 12:20:15 pid 5032 compute end .547s
Perforce server info:
	2024/04/03 12:20:49 pid 5032 compute end 34.9s
Perforce server info:
	2024/04/03 12:21:12 pid 5032 compute end 57.5s
Perforce server info:
	2024/04/03 12:21:15 pid 5032 compute end 60.9s
Perforce server info:
	2024/04/03 12:21:15 pid 5032 completed 60.9s
Perforce server info:
	2024/04/03 12:20:14 pid 5032 fred@fred-Dinner-dev 10.1.2.212 [UnrealGameSync/v84] 'user-changes -m1 -ssubmitted //fred-Dinner-dev/*.cs@<=764311 //fred-Dinner-dev/Engine/....cs@<=764311 //fred-Dinner-dev/Dinner/....cs@<=764311'
--- lapse 60.9s
--- memory cmd/proc 8mb/442mb
--- rpc msgs/size in+out 0+12/0mb+0mb himarks 64836/523588 snd/rcv .000s/.000s
--- filetotals (svr) send/recv files+bytes 0+0mb/0+0mb
--- db.rev
---   pages in+out+cached 1558725+0+96
---   locks read/write 0/0 rows get+pos+scan put+del 0+56+22442266 0+0
---   peek count 21 wait+held total/max 0ms+60953ms/0ms+34390ms
--- db.change
---   pages in+out+cached 35+0+10
---   locks read/write 0/0 rows get+pos+scan put+del 0+12+12 0+0
---   peek count 21 wait+held total/max 0ms+60953ms/0ms+34390ms
`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	// assert.Equal(t, "", output[0])
	assert.JSONEq(t, cleanJSON(`{"processKey":"adb2b3c890b15d59f748c064e2c181b6","cmd":"user-changes","pid":5032,"lineNo":2,"user":"fred","workspace":"fred-Dinner-dev","computeLapse":60.9,"completedLapse":60.9,"ip":"10.1.2.212","app":"UnrealGameSync/v84","args":"-m1 -ssubmitted //fred-Dinner-dev/*.cs@\u003c=764311 //fred-Dinner-dev/Engine/....cs@\u003c=764311 //fred-Dinner-dev/Dinner/....cs@\u003c=764311","startTime":"2024/04/03 12:20:14","endTime":"2024/04/03 12:21:15","running":1,"memMB":8,"memPeakMB":442,"rpcMsgsOut":12,"rpcHimarkFwd":64836,"rpcHimarkRev":523588,"cmdError":false,"tables":[{"tableName":"change","pagesIn":35,"pagesCached":10,"posRows":12,"scanRows":12,"peekCount":21,"totalPeekHeld":60953,"maxPeekHeld":34390},{"tableName":"rev","pagesIn":1558725,"pagesCached":96,"posRows":56,"scanRows":22442266,"peekCount":21,"totalPeekHeld":60953,"maxPeekHeld":34390}]}`),
		cleanJSON(output[0]))
}

func TestRemovedFromMonitorTable(t *testing.T) {
	testInput := `
Perforce server info:
	2024/06/10 08:08:01 pid 2064774 p4sdp@p4svr 127.0.0.1 [p4/2024.1.PREP-TEST_ONLY/LINUX26X86_64/2589505] 'user-counters'
Perforce server info:
	2024/06/10 08:08:01 pid 2064774 completed .005s 0+5us 0+0io 0+0net 11896k 0pf
Perforce server info:
	2024/06/10 08:08:01 pid 2064774 p4sdp@p4svr 127.0.0.1 [p4/2024.1.PREP-TEST_ONLY/LINUX26X86_64/2589505] 'user-counters'
--- lapse .005s
--- usage 0+5us 0+8io 0+0net 11896k 0pf
--- memory cmd/proc 28mb/28mb
--- rpc msgs/size in+out 2+40/0mb+0mb himarks 97604/97604 snd/rcv .000s/.000s
--- filetotals (svr) send/recv files+bytes 0+0mb/0+0mb

Perforce server info:
	2024/06/10 08:09:02 pid 2064774 unknown@unknown 127.0.0.1 [unknown] 'Init()' exited unexpectedly, removed from monitor table.
`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	// assert.Equal(t, "", output[0])
	assert.JSONEq(t, cleanJSON(`{"app":"p4/2024.1.PREP-TEST_ONLY/LINUX26X86_64/2589505", "args":"", "cmd":"user-counters", "cmdError":true, "completedLapse":0.005, "diskOut":8, "endTime":"2024/06/10 08:08:01", "ip":"127.0.0.1", "lineNo":2, "maxRss":11896, "memMB":28, "memPeakMB":28, "pid":2.064774e+06, "processKey":"6b134fc7c84aa5d25dcaa814e13a7848", "rpcHimarkFwd":97604, "rpcHimarkRev":97604, "rpcMsgsIn":2, "rpcMsgsOut":40, "running":1, "sCpu":5, "startTime":"2024/06/10 08:08:01", "user":"p4sdp", "workspace":"p4svr","tables":[]}`),
		cleanJSON(output[0]))
}

func TestRemovedFromMonitorTable2(t *testing.T) {
	testInput := `
Perforce server info:
	2024/06/10 06:12:03 pid 1837049 git-fusion-user@git-fusion--gfprod3-076a3fa2-272b-11ef-8240-0050568421b4 127.0.0.1/10.5.40.30 [Git Fusion/2017.1.SNAPSHOT/1778910 (2019/04/01)/v82 (brokered)] 'user-key git-fusion-auth-keys-last-changenum-gfprod3'
Perforce server info:
	2024/06/10 06:12:03 pid 1837049 completed .002s 1+1us 0+0io 0+0net 13876k 0pf
Perforce server info:
	2024/06/10 06:12:03 pid 1837049 git-fusion-user@git-fusion--gfprod3-076a3fa2-272b-11ef-8240-0050568421b4 127.0.0.1/10.5.40.30 [Git Fusion/2017.1.SNAPSHOT/1778910 (2019/04/01)/v82 (brokered)] 'user-key git-fusion-auth-keys-last-changenum-gfprod3'
--- lapse .002s
--- usage 1+1us 0+8io 0+0net 13876k 0pf
--- memory cmd/proc 30mb/30mb
--- rpc msgs/size in+out 0+1/0mb+0mb himarks 97604/318788 snd/rcv .000s/.000s
--- filetotals (svr) send/recv files+bytes 0+0mb/0+0mb

Perforce server info:
	2024/06/10 06:12:03 pid 1837049 git-fusion-user@git-fusion--gfprod3-076a3fa2-272b-11ef-8240-0050568421b4 127.0.0.1/10.5.40.30 [Git Fusion/2017.1.SNAPSHOT/1778910 (2019/04/01)/v82 (brokered)] 'user-key git-fusion-auth-keys-last-changenum-gfprod3'
--- clientEntity/git-fusion--gfprod3-076a3fa2-272b-11ef-8240-0050568421b4(W)
---   total lock wait+held read/write 0ms+0ms/0ms+68ms

Perforce server info:
	2024/06/10 06:12:03 pid 1837049 git-fusion-user@git-fusion--gfprod3-076a3fa2-272b-11ef-8240-0050568421b4 127.0.0.1/10.5.40.30 [Git Fusion/2017.1.SNAPSHOT/1778910 (2019/04/01)/v82 (brokered)] 'user-key git-fusion-auth-keys-last-changenum-gfprod3'
--- clients/git-fusion--gfprod3-076a3fa2-272b-11ef-8240-0050568421b4(W)
---   total lock wait+held read/write 0ms+0ms/0ms+70ms

Perforce server info:
	2024/06/10 06:13:02 pid 1837049 git-fusion-user@git-fusion--gfprod3-076a3fa2-272b-11ef-8240-0050568421b4 10.5.40.30 [Git Fusion/2017.1.SNAPSHOT/1778910 (2019/04/01)/v82 (brokered)] 'IDLE' exited unexpectedly, removed from monitor table.`
	output := parseLogLines(testInput)
	assert.Equal(t, 1, len(output))
	// assert.Equal(t, "", output[0])
	assert.JSONEq(t, cleanJSON(`{"app":"Git Fusion/2017.1.SNAPSHOT/1778910 (2019/04/01)/v82 (brokered)", "args":"git-fusion-auth-keys-last-changenum-gfprod3", "cmd":"user-key", "cmdError":true, "completedLapse":0.002, "diskOut":8, "endTime":"2024/06/10 06:12:03", "ip":"127.0.0.1/10.5.40.30", "lineNo":2, "maxRss":13876, "memMB":30, "memPeakMB":30, "pid":1.837049e+06, "processKey":"e60035bfd064b9c153c732d3b6a9206a", "rpcHimarkFwd":97604, "rpcHimarkRev":318788, "rpcMsgsOut":1, "running":1, "sCpu":1, "startTime":"2024/06/10 06:12:03", "uCpu":1, "user":"git-fusion-user", "workspace":"git-fusion--gfprod3-076a3fa2-272b-11ef-8240-0050568421b4","tables":[]}`),
		cleanJSON(output[0]))
}
