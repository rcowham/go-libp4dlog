package p4dlog

import (
	"bufio"
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

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

	inchan := make(chan []byte, 100)
	cmdchan := make(chan Command, 100)

	fp := NewP4dFileParser(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fp.LogParser(ctx, inchan, cmdchan)

	scanner := bufio.NewScanner(strings.NewReader(input))
	for scanner.Scan() {
		line := scanner.Bytes()
		inchan <- line
	}
	close(inchan)

	output := []string{}
	for cmd := range cmdchan {
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
	assert.JSONEq(t, `{"processKey":"4d4e5096f7b732e4ce95230ef085bf51","cmd":"user-sync","pid":1616,"lineNo":2,"user":"robert","workspace":"robert-test","computeLapse":0.031,"completedLapse":0.031,"ip":"127.0.0.1","app":"Microsoft Visual Studio 2013/12.0.21005.1","args":"//...","startTime":"2015/09/02 15:23:09","endTime":"2015/09/02 15:23:09","running":0,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[]}`,
		output[0])

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
	assert.JSONEq(t, `{"processKey":"1f360d628fb2c9fe5354b8cf5022f7bd","cmd":"user-sync","pid":1616,"lineNo":2,"user":"robert","workspace":"robert-test","computeLapse":0.031,"completedLapse":0.031,"ip":"127.0.0.1","app":"Microsoft® Visual Studio® 2013/12.0.21005.1","args":"//...","startTime":"2015/09/02 15:23:09","endTime":"2015/09/02 15:23:09","running":0,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[]}`,
		output[0])

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
	assert.JSONEq(t, `{"processKey":"7868f2723d35c6cb91784afa6bef4a7a","cmd":"user-client","pid":81805,"lineNo":2,"user":"bruno","workspace":"robert_cowham-dvcs-1487082773","computeLapse":0,"completedLapse":0.009,"ip":"10.62.185.98","app":"p4/2016.2/LINUX26X86_64/1468155","args":"-d -f bruno.139631598948304.irp210-h03","startTime":"2017/02/15 13:46:42","endTime":"2017/02/15 13:46:42","running":0,"uCpu":10,"sCpu":11,"diskIn":12,"diskOut":13,"ipcIn":14,"ipcOut":15,"maxRss":4088,"pageFaults":0,"rpcMsgsIn":20,"rpcMsgsOut":21,"rpcSizeIn":22,"rpcSizeOut":23,"rpcHimarkFwd":318788,"rpcHimarkRev":318789,"rpcSnd":0.001,"rpcRcv":0.002,"cmdError":false,"tables":[{"tableName":"have","pagesIn":1,"pagesOut":2,"pagesCached":3,"pagesSplitInternal":41,"pagesSplitLeaf":42,"readLocks":4,"writeLocks":5,"getRows":6,"posRows":7,"scanRows":8,"putRows":9,"delRows":10,"totalReadWait":12,"totalReadHeld":13,"totalWriteWait":14,"totalWriteHeld":15,"maxReadWait":32,"maxReadHeld":33,"maxWriteWait":34,"maxWriteHeld":35,"peekCount":20,"totalPeekWait":21,"totalPeekHeld":22,"maxPeekWait":23,"maxPeekHeld":24,"triggerLapse":0}]}`,
		output[0])
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
	assert.JSONEq(t, `{"processKey":"d0ae06fd40d95180ca403a9c30084a66","cmd":"user-counter","pid":14769,"lineNo":2,"user":"perforce","workspace":"~tmp.1482305462.13038.585a2fb6041cc1.60954329","computeLapse":0,"completedLapse":0.003,"ip":"192.168.18.31","app":"SWARM/2016.2/1446446","args":"-u swarm-activity-fffec3dd","startTime":"2016/12/21 08:39:39","endTime":"2016/12/21 08:39:39","running":0,"uCpu":4,"sCpu":0,"diskIn":0,"diskOut":16,"ipcIn":0,"ipcOut":0,"maxRss":6432,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[]}`,
		output[0])
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
	assert.JSONEq(t, `{"processKey":"1eec998ae9cc1ce44058f4503a01f2c0","cmd":"user-key","pid":10664,"lineNo":2,"user":"git-fusion-user","workspace":"GF-TRIGGER-567d67de-962","computeLapse":0,"completedLapse":0.844,"ip":"10.100.104.199","app":"p4/2016.1/NTX64/1396108","args":"git-fusion-reviews-common-lock-owner","startTime":"2016/10/19 12:01:08","endTime":"2016/10/19 12:01:09","running":0,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":2,"rpcMsgsOut":3,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":523588,"rpcHimarkRev":523588,"rpcSnd":0,"rpcRcv":0.015,"cmdError":false,"tables":[{"tableName":"group","pagesIn":7,"pagesOut":0,"pagesCached":6,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":1,"writeLocks":0,"getRows":0,"posRows":3,"scanRows":67,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":15,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"nameval","pagesIn":6,"pagesOut":4,"pagesCached":4,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":0,"writeLocks":1,"getRows":0,"posRows":0,"scanRows":0,"putRows":1,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":16,"totalWriteHeld":15,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"protect","pagesIn":282,"pagesOut":0,"pagesCached":96,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":1,"writeLocks":0,"getRows":0,"posRows":1,"scanRows":14495,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":641,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"trigger","pagesIn":21,"pagesOut":0,"pagesCached":20,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":1,"writeLocks":0,"getRows":0,"posRows":1,"scanRows":486,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":47,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"user","pagesIn":4,"pagesOut":0,"pagesCached":3,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":1,"writeLocks":0,"getRows":1,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":16,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0}]}`,
		output[0])
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
	assert.JSONEq(t, `{"processKey":"e2bf456007fe305acdae759996dbbeb9","cmd":"user-reconcile","pid":4500,"lineNo":6,"user":"robert","workspace":"robert-test","computeLapse":0,"completedLapse":0,"ip":"127.0.0.1","app":"Microsoft Visual Studio 2013/12.0.21005.1","args":"-eadf -c 12253 c:\\temp\\robert-test\\test\\VEER!-%-#-@-$-\u0026-(-)\\fred - Copy.txt c:\\temp\\robert-test\\test\\VEER!-%-#-@-$-\u0026-(-)\\fred - Copy.txt c:\\temp\\robert-test\\test\\VEER!-%-#-@-$-\u0026-(-)\\fred - Copy.txt c:\\temp\\robert-test\\test\\VEER!-%-#-@-$-\u0026-(-)\\fred - Copy.txt","startTime":"2015/09/02 16:43:36","endTime":"0001/01/01 00:00:00","running":1,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[]}`,
		output[0])
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
	Server network estimates: files added/updated/deleted=1/3/0, bytes added/updated=111325/813906
Perforce server info:
	2017/02/15 10:11:30 pid 4917 completed .034s 19+4us 0+8io 0+0net 8996k 0pf`
	output := parseLogLines(testInput)
	assert.Equal(t, 2, len(output))
	assert.JSONEq(t, `{"processKey":"4964a5f82541f47985f0965ab47c1e39","cmd":"user-have","pid":4917,"lineNo":2,"user":"bruno","workspace":"bruno.140451462678608","computeLapse":0,"completedLapse":0.002,"ip":"10.62.185.99","app":"unnamed p4-python script/v81","args":"","startTime":"2017/02/15 10:11:30","endTime":"2017/02/15 10:11:30","running":0,"uCpu":2,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":8932,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[]}`,
		output[0])
	assert.JSONEq(t, `{"processKey":"7c65428ac3b32f6f42f84ead5694ffb4","cmd":"user-sync","pid":4917,"lineNo":6,"user":"bruno","workspace":"bruno.140451462678608","computeLapse":0.02,"completedLapse":0.034,"ip":"10.62.185.99","app":"unnamed p4-python script/v81","args":"//bruno.140451462678608/...","startTime":"2017/02/15 10:11:30","endTime":"2017/02/15 10:11:30","running":1,"uCpu":19,"sCpu":4,"diskIn":0,"diskOut":8,"ipcIn":0,"ipcOut":0,"maxRss":8996,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[]}`,
		output[1])
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
	assert.JSONEq(t, `{"processKey":"bea947227d9ec7f4300a0ea889886934","cmd":"rmt-FileFetch","pid":113249,"lineNo":2,"user":"serviceUser","workspace":"unknown","computeLapse":0,"completedLapse":0,"ip":"10.62.185.99","app":"p4d/2016.2/LINUX26X86_64/1468155","args":"","startTime":"2017/03/06 11:53:50","endTime":"2017/03/06 11:53:50","running":1,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":2,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":318788,"rpcHimarkRev":318788,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[{"tableName":"user","pagesIn":2,"pagesOut":0,"pagesCached":2,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":1,"writeLocks":0,"getRows":1,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0}]}`,
		output[0])
	assert.JSONEq(t, `{"processKey":"bea947227d9ec7f4300a0ea889886934.9","cmd":"rmt-FileFetch","pid":113249,"lineNo":9,"user":"serviceUser","workspace":"unknown","computeLapse":0,"completedLapse":0,"ip":"10.62.185.99","app":"p4d/2016.2/LINUX26X86_64/1468155","args":"","startTime":"2017/03/06 11:53:50","endTime":"2017/03/06 11:53:50","running":1,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":2,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":318788,"rpcHimarkRev":318788,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[{"tableName":"user","pagesIn":1,"pagesOut":0,"pagesCached":2,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":1,"writeLocks":0,"getRows":1,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0}]}`,
		output[1])
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
var multiExp1 = `{"processKey":"f9a64670da4d77a44225be236974bc8b","cmd":"user-sync","pid":1616,"lineNo":2,"user":"robert","workspace":"robert-test","computeLapse":0.031,"completedLapse":0.031,"ip":"127.0.0.1","app":"p4/2016.2/LINUX26X86_64/1598668","args":"//...","startTime":"2015/09/02 15:23:09","endTime":"2015/09/02 15:23:09","running":0,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[]}`
var multiExp2 = `{"processKey":"2908cdb35e4b82dae3d0b403ef0c3bbf","cmd":"user-sync","pid":1534,"lineNo":6,"user":"fred","workspace":"fred-test","computeLapse":0.021,"completedLapse":0.041,"ip":"127.0.0.1","app":"p4/2016.2/LINUX26X86_64/1598668","args":"//...","startTime":"2015/09/02 15:23:09","endTime":"2015/09/02 15:23:09","running":1,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[]}`

func TestLogParseMulti(t *testing.T) {
	output := parseLogLines(multiInput)
	assert.Equal(t, 2, len(output))
	sort.Strings(output)
	assert.JSONEq(t, multiExp1, output[1])
	assert.JSONEq(t, multiExp2, output[0])
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
	assert.JSONEq(t, `{"processKey":"128e10d7fe570c2d2f5f7f03e1186827","cmd":"dm-CommitSubmit","pid":25568,"lineNo":15,"user":"fred","workspace":"lon_ws","computeLapse":0,"completedLapse":1.38,"ip":"10.1.2.3","app":"p4/2016.2/LINUX26X86_64/1598668","args":"","startTime":"2018/06/10 23:30:08","endTime":"2018/06/10 23:30:09","running":1,"uCpu":34,"sCpu":61,"diskIn":59680,"diskOut":59904,"ipcIn":0,"ipcOut":0,"maxRss":127728,"pageFaults":1,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[{"tableName":"archmap","pagesIn":0,"pagesOut":0,"pagesCached":0,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":0,"writeLocks":0,"getRows":0,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":780,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"integed","pagesIn":0,"pagesOut":0,"pagesCached":0,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":0,"writeLocks":0,"getRows":0,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":795,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0}]}`,
		output[0])
	assert.JSONEq(t, `{"processKey":"465f0a630b021d3c695e90924a757b75","cmd":"user-submit","pid":25568,"lineNo":2,"user":"fred","workspace":"lon_ws","computeLapse":0,"completedLapse":0.178,"ip":"10.1.2.3","app":"p4/2016.2/LINUX26X86_64/1598668","args":"-i","startTime":"2018/06/10 23:30:06","endTime":"2018/06/10 23:30:07","running":0,"uCpu":96,"sCpu":17,"diskIn":0,"diskOut":208,"ipcIn":0,"ipcOut":0,"maxRss":15668,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[]}`,
		output[1])
	assert.JSONEq(t, `{"processKey":"78dbd54644e624a9c6f5c338a0864d2a","cmd":"dm-SubmitChange","pid":25568,"lineNo":7,"user":"fred","workspace":"lon_ws","computeLapse":0.252,"completedLapse":1.38,"ip":"10.1.2.3","app":"p4/2016.2/LINUX26X86_64/1598668","args":"","startTime":"2018/06/10 23:30:07","endTime":"2018/06/10 23:30:08","running":1,"uCpu":490,"sCpu":165,"diskIn":0,"diskOut":178824,"ipcIn":0,"ipcOut":0,"maxRss":127728,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[]}`,
		output[2])
	// assert.Equal(t, `asdf`,
	// 	output[3])
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
	assert.JSONEq(t, `{"processKey":"9b2bf87ce1b8e88d0d89cf44cffc4a8c","cmd":"user-change","pid":4496,"lineNo":2,"user":"lcheng","workspace":"lcheng","computeLapse":0,"completedLapse":0.015,"ip":"10.100.72.195","app":"P4V/NTX64/2014.1/888424/v76","args":"-o","startTime":"2016/10/19 14:53:48","endTime":"2016/10/19 14:53:48","running":0,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":1,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":523588,"rpcHimarkRev":64836,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[{"tableName":"group","pagesIn":1,"pagesOut":0,"pagesCached":7,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":1,"writeLocks":0,"getRows":0,"posRows":6,"scanRows":11,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"user","pagesIn":1,"pagesOut":0,"pagesCached":3,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":1,"writeLocks":0,"getRows":1,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0}]}`,
		output[0])
	assert.JSONEq(t, `{"processKey":"9b2bf87ce1b8e88d0d89cf44cffc4a8c.18","cmd":"user-change","pid":4496,"lineNo":18,"user":"lcheng","workspace":"lcheng","computeLapse":0,"completedLapse":0.016,"ip":"10.100.72.195","app":"P4V/NTX64/2014.1/888424/v76","args":"-o","startTime":"2016/10/19 14:53:48","endTime":"2016/10/19 14:53:48","running":1,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":1,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":523588,"rpcHimarkRev":64836,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[{"tableName":"group","pagesIn":1,"pagesOut":0,"pagesCached":7,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":1,"writeLocks":0,"getRows":0,"posRows":6,"scanRows":11,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"user","pagesIn":1,"pagesOut":0,"pagesCached":3,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":1,"writeLocks":0,"getRows":1,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0}]}`,
		output[1])
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
	assert.JSONEq(t, `{"processKey":"25aeba7a5658170fea61117076fa00d5","cmd":"user-change","pid":148469,"lineNo":2,"user":"Fred","workspace":"LONWS","computeLapse":0,"completedLapse":0.413,"ip":"10.40.16.14/10.40.48.29","app":"3DSMax/1.0.0.0","args":"-i","startTime":"2017/12/07 15:00:21","endTime":"2017/12/07 15:00:21","running":0,"uCpu":10,"sCpu":11,"diskIn":12,"diskOut":13,"ipcIn":14,"ipcOut":15,"maxRss":4088,"pageFaults":22,"rpcMsgsIn":20,"rpcMsgsOut":21,"rpcSizeIn":22,"rpcSizeOut":23,"rpcHimarkFwd":318788,"rpcHimarkRev":318789,"rpcSnd":0.001,"rpcRcv":0.002,"cmdError":false,"tables":[{"tableName":"counters","pagesIn":6,"pagesOut":3,"pagesCached":2,"pagesSplitInternal":41,"pagesSplitLeaf":42,"readLocks":0,"writeLocks":2,"getRows":2,"posRows":0,"scanRows":0,"putRows":1,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"trigger_swarm.changesave","pagesIn":0,"pagesOut":0,"pagesCached":0,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":0,"writeLocks":0,"getRows":0,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0.044}]}`,
		output[0])
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
	assert.Equal(t, `{"processKey":"128e10d7fe570c2d2f5f7f03e1186827","cmd":"dm-CommitSubmit","pid":25568,"lineNo":16,"user":"fred","workspace":"lon_ws","computeLapse":0,"completedLapse":1.38,"ip":"10.1.2.3","app":"p4/2016.2/LINUX26X86_64/1598668","args":"","startTime":"2018/06/10 23:30:08","endTime":"2018/06/10 23:30:09","running":1,"uCpu":34,"sCpu":61,"diskIn":59680,"diskOut":59904,"ipcIn":0,"ipcOut":0,"maxRss":127728,"pageFaults":1,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[{"tableName":"archmap","pagesIn":0,"pagesOut":0,"pagesCached":0,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":0,"writeLocks":0,"getRows":0,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":780,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"integed","pagesIn":0,"pagesOut":0,"pagesCached":0,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":0,"writeLocks":0,"getRows":0,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":795,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0}]}`,
		output[0])
	assert.Equal(t, `{"processKey":"441371d8e17558bfb8e6cf7c1ca7b3ac","cmd":"user-change","pid":148469,"lineNo":2,"user":"fred","workspace":"LONWS","computeLapse":0,"completedLapse":0.413,"ip":"10.40.16.14/10.40.48.29","app":"3DSMax/1.0.0.0","args":"-i","startTime":"2017/12/07 15:00:21","endTime":"2017/12/07 15:00:21","running":0,"uCpu":10,"sCpu":11,"diskIn":12,"diskOut":13,"ipcIn":14,"ipcOut":15,"maxRss":4088,"pageFaults":22,"rpcMsgsIn":20,"rpcMsgsOut":21,"rpcSizeIn":22,"rpcSizeOut":23,"rpcHimarkFwd":318788,"rpcHimarkRev":318789,"rpcSnd":0.001,"rpcRcv":0.002,"cmdError":false,"tables":[{"tableName":"counters","pagesIn":6,"pagesOut":3,"pagesCached":2,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":0,"writeLocks":2,"getRows":2,"posRows":0,"scanRows":0,"putRows":1,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"trigger_swarm.changesave","pagesIn":0,"pagesOut":0,"pagesCached":0,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":0,"writeLocks":0,"getRows":0,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0.044}]}`,
		output[1])
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
	assert.JSONEq(t, `{"processKey":"227e3b54b1283b1fef89bc5843eb87d5","cmd":"user-resolved","pid":25883,"lineNo":2,"user":"user1","workspace":"ws1","computeLapse":0,"completedLapse":0,"ip":"10.1.3.158","app":"IntelliJ_IDEA_resolved/2018.1/LINUX26X86_64/1637071","args":"/home/user1/perforce_ws/ws1/.idea/... /home/user1/perforce_ws/ws1/...","startTime":"2019/12/20 09:42:15","endTime":"0001/01/01 00:00:00","running":0,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"cmdError":true,"tables":[]}`,
		output[0])
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
	assert.JSONEq(t, `{"processKey":"642f3b3976afda703fb97524581913b7","cmd":"pull","pid":6170,"lineNo":2,"user":"svc_wok","workspace":"unknown","computeLapse":0,"completedLapse":0,"ip":"background","app":"p4d/2019.2/LINUX26X86_64/1891638","args":"-i 1","startTime":"2019/12/20 08:00:03","endTime":"2019/12/20 08:00:03","running":1,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[{"tableName":"view","pagesIn":2,"pagesOut":3,"pagesCached":96,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":4,"writeLocks":5,"getRows":6,"posRows":7,"scanRows":8,"putRows":9,"delRows":10,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0}]}`,
		output[0])
	assert.JSONEq(t, `{"processKey":"642f3b3976afda703fb97524581913b7.10","cmd":"pull","pid":6170,"lineNo":10,"user":"svc_wok","workspace":"unknown","computeLapse":0,"completedLapse":0,"ip":"background","app":"p4d/2019.2/LINUX26X86_64/1891638","args":"-i 1","startTime":"2019/12/20 08:00:03","endTime":"2019/12/20 08:00:03","running":1,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[{"tableName":"domain","pagesIn":2,"pagesOut":3,"pagesCached":96,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":0,"writeLocks":1,"getRows":0,"posRows":0,"scanRows":0,"putRows":1,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0}]}`,
		output[1])
	assert.JSONEq(t, `{"processKey":"642f3b3976afda703fb97524581913b7.18","cmd":"pull","pid":6170,"lineNo":18,"user":"svc_wok","workspace":"unknown","computeLapse":0,"completedLapse":0,"ip":"background","app":"p4d/2019.2/LINUX26X86_64/1891638","args":"-i 1","startTime":"2019/12/20 08:00:03","endTime":"2019/12/20 08:00:03","running":1,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[{"tableName":"domain","pagesIn":2,"pagesOut":3,"pagesCached":96,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":0,"writeLocks":1,"getRows":0,"posRows":0,"scanRows":0,"putRows":0,"delRows":1,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"view","pagesIn":2,"pagesOut":3,"pagesCached":96,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":0,"writeLocks":1,"getRows":0,"posRows":0,"scanRows":0,"putRows":0,"delRows":1,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0}]}`,
		output[2])
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
	assert.JSONEq(t, `{"processKey":"026c2d4135085764d23fd21f41d30f77","cmd":"user-sync","pid":145941,"lineNo":2,"user":"builder","workspace":"LON","computeLapse":0.14,"completedLapse":0.111,"ip":"10.10.16.171/10.10.20.195","app":"AutoWorker/1.0.0.0","args":"//assets/level/instances.xml","startTime":"2017/12/07 15:00:01","endTime":"2017/12/07 15:00:01","running":0,"uCpu":77,"sCpu":25,"diskIn":112,"diskOut":3136,"ipcIn":0,"ipcOut":0,"maxRss":4964,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[]}`,
		output[0])
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
	assert.Equal(t, `{"processKey":"44c92f3be809fd15dfc26cc8fb359216","cmd":"pull","pid":55998,"lineNo":38,"user":"svc0","workspace":"unknown","computeLapse":0,"completedLapse":0,"ip":"background","app":"p4d/2018.1/DARWIN90X86_64/1660568","args":"-u -i 1 -b 1","startTime":"2018/06/01 04:29:44","endTime":"2018/06/01 04:29:44","running":2,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[{"tableName":"rdb.lbr","pagesIn":7,"pagesOut":4,"pagesCached":2,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":0,"writeLocks":3,"getRows":1,"posRows":1,"scanRows":4,"putRows":1,"delRows":1,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0}]}`,
		output[0])
	assert.Equal(t, `{"processKey":"9e39beedee815db46bb4c870c11a0b8d","cmd":"pull","pid":55997,"lineNo":2,"user":"svc0","workspace":"unknown","computeLapse":0,"completedLapse":0,"ip":"background","app":"p4d/2018.1/DARWIN90X86_64/1660568","args":"-I 100 -b 1","startTime":"2018/06/01 04:29:43","endTime":"2018/06/01 04:29:43","running":1,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[{"tableName":"counters","pagesIn":2,"pagesOut":0,"pagesCached":2,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":0,"writeLocks":1,"getRows":1,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0}]}`,
		output[1])
	assert.Equal(t, `{"processKey":"9e39beedee815db46bb4c870c11a0b8d.10","cmd":"pull","pid":55997,"lineNo":10,"user":"svc0","workspace":"unknown","computeLapse":0,"completedLapse":0,"ip":"background","app":"p4d/2018.1/DARWIN90X86_64/1660568","args":"-I 100 -b 1","startTime":"2018/06/01 04:29:43","endTime":"2018/06/01 04:29:43","running":1,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[{"tableName":"counters","pagesIn":4,"pagesOut":3,"pagesCached":2,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":0,"writeLocks":2,"getRows":0,"posRows":0,"scanRows":0,"putRows":1,"delRows":1,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0}]}`,
		output[2])
	assert.Equal(t, `{"processKey":"9e39beedee815db46bb4c870c11a0b8d.18","cmd":"pull","pid":55997,"lineNo":18,"user":"svc0","workspace":"unknown","computeLapse":0,"completedLapse":0.001,"ip":"background","app":"p4d/2018.1/DARWIN90X86_64/1660568","args":"-I 100 -b 1","startTime":"2018/06/01 04:29:43","endTime":"2018/06/01 04:29:43","running":1,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[{"tableName":"change","pagesIn":4,"pagesOut":3,"pagesCached":2,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":0,"writeLocks":1,"getRows":0,"posRows":0,"scanRows":0,"putRows":1,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"changex","pagesIn":4,"pagesOut":3,"pagesCached":2,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":0,"writeLocks":1,"getRows":0,"posRows":0,"scanRows":0,"putRows":1,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"counters","pagesIn":2,"pagesOut":3,"pagesCached":2,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":0,"writeLocks":1,"getRows":1,"posRows":0,"scanRows":0,"putRows":1,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"desc","pagesIn":4,"pagesOut":3,"pagesCached":2,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":0,"writeLocks":1,"getRows":0,"posRows":0,"scanRows":0,"putRows":1,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0}]}`,
		output[3])
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
	assert.JSONEq(t, `{"processKey":"f7d483631e94d16adde6c5306be15fbe","cmd":"user-revert","pid":22245,"lineNo":2,"user":"auto","workspace":"archive_auto","computeLapse":0,"completedLapse":6.92,"ip":"127.0.0.1","app":"archive/v60","args":"/usr/local/arch/datastore/...","startTime":"2018/09/06 06:00:02","endTime":"2018/09/06 06:00:02","running":0,"uCpu":6901,"sCpu":4,"diskIn":32,"diskOut":8,"ipcIn":0,"ipcOut":0,"maxRss":19996,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[{"tableName":"protect","pagesIn":0,"pagesOut":0,"pagesCached":0,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":0,"writeLocks":0,"getRows":0,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":4,"totalReadHeld":6875,"totalWriteWait":5,"totalWriteHeld":6,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"resolve","pagesIn":0,"pagesOut":0,"pagesCached":0,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":0,"writeLocks":0,"getRows":0,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":23792,"totalReadHeld":3,"totalWriteWait":2,"totalWriteHeld":1,"maxReadWait":23792,"maxReadHeld":3,"maxWriteWait":2,"maxWriteHeld":1,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0}]}`,
		output[0])
	assert.Equal(t, `{"processKey":"f7d483631e94d16adde6c5306be15fbe","cmd":"user-revert","pid":22245,"lineNo":2,"user":"auto","workspace":"archive_auto","computeLapse":0,"completedLapse":6.92,"ip":"127.0.0.1","app":"archive/v60","args":"/usr/local/arch/datastore/...","startTime":"2018/09/06 06:00:02","endTime":"2018/09/06 06:00:02","running":0,"uCpu":6901,"sCpu":4,"diskIn":32,"diskOut":8,"ipcIn":0,"ipcOut":0,"maxRss":19996,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[{"tableName":"protect","pagesIn":0,"pagesOut":0,"pagesCached":0,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":0,"writeLocks":0,"getRows":0,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":4,"totalReadHeld":6875,"totalWriteWait":5,"totalWriteHeld":6,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"resolve","pagesIn":0,"pagesOut":0,"pagesCached":0,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":0,"writeLocks":0,"getRows":0,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":23792,"totalReadHeld":3,"totalWriteWait":2,"totalWriteHeld":1,"maxReadWait":23792,"maxReadHeld":3,"maxWriteWait":2,"maxWriteHeld":1,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0}]}`,
		output[0])
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
	2020/03/11 06:08:17 pid 15854 completed .338s 0+4us 0+56io 0+0net 8356k 0pf 

Perforce server info:
	2020/03/11 06:08:16 pid 15855 fred@fred_ws 10.1.4.213/10.1.3.243 [Helix P4V/NTX64/2019.2/1904275/v86] 'user-change -i' trigger swarm.changesave
lapse .076s
Perforce server info:
	2020/03/11 06:08:16 pid 15855 fred@fred_ws 10.1.4.213/10.1.3.243 [Helix P4V/NTX64/2019.2/1904275/v86] 'user-change -i'
--- storageup/storageup(R)
---   total lock wait+held read/write 0ms+2ms/0ms+0ms

Perforce server info:
	2020/03/11 06:08:16 pid 15855 fred@fred_ws 10.1.4.213/10.1.3.243 [Helix P4V/NTX64/2019.2/1904275/v86] 'user-change -i'
--- storageup/storagemasterup(R)
---   total lock wait+held read/write 0ms+2ms/0ms+0ms

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
	assert.Equal(t, `{"processKey":"b9ec8da8ea642419a06f8ac4060f261c","cmd":"rmt-Journal","pid":17916,"lineNo":4,"user":"svc_p4d_ha_chi","workspace":"unknown","computeLapse":0,"completedLapse":0.202,"ip":"10.5.70.41","app":"p4d/2019.2/LINUX26X86_64/1908095","args":"","startTime":"2020/03/11 06:08:16","endTime":"2020/03/11 06:08:16","running":2,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":1,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":280100,"rpcHimarkRev":278660,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[{"tableName":"counters","pagesIn":6,"pagesOut":0,"pagesCached":2,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":6,"writeLocks":0,"getRows":6,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0}]}`,
		output[0])
	assert.Equal(t, `{"processKey":"b9ec8da8ea642419a06f8ac4060f261c.13","cmd":"rmt-Journal","pid":17916,"lineNo":13,"user":"svc_p4d_ha_chi","workspace":"unknown","computeLapse":0,"completedLapse":0.001,"ip":"10.5.70.41","app":"p4d/2019.2/LINUX26X86_64/1908095","args":"","startTime":"2020/03/11 06:08:16","endTime":"2020/03/11 06:08:16","running":2,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":1,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":280100,"rpcHimarkRev":278660,"rpcSnd":0,"rpcRcv":0,"cmdError":false,"tables":[{"tableName":"counters","pagesIn":1,"pagesOut":0,"pagesCached":2,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":1,"writeLocks":0,"getRows":1,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0}]}`,
		output[1])
	assert.Equal(t, `{"processKey":"b9f9aee10027df004a0e35a3c9931e27","cmd":"user-change","pid":15855,"lineNo":2,"user":"fred","workspace":"fred_ws","computeLapse":0,"completedLapse":0.276,"ip":"10.1.4.213/10.1.3.243","app":"Helix P4V/NTX64/2019.2/1904275/v86","args":"-i","startTime":"2020/03/11 06:08:16","endTime":"2020/03/11 06:08:17","running":0,"uCpu":4,"sCpu":4,"diskIn":256,"diskOut":240,"ipcIn":0,"ipcOut":0,"maxRss":9212,"pageFaults":0,"rpcMsgsIn":3,"rpcMsgsOut":5,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":280100,"rpcHimarkRev":280100,"rpcSnd":0,"rpcRcv":0.19,"cmdError":false,"tables":[{"tableName":"counters","pagesIn":7,"pagesOut":6,"pagesCached":2,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":1,"writeLocks":2,"getRows":3,"posRows":0,"scanRows":0,"putRows":2,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"monitor","pagesIn":2,"pagesOut":4,"pagesCached":256,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":0,"writeLocks":2,"getRows":0,"posRows":0,"scanRows":0,"putRows":2,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"protect","pagesIn":9,"pagesOut":0,"pagesCached":7,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":1,"writeLocks":0,"getRows":0,"posRows":1,"scanRows":345,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":1,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"trigger_swarm.changesave","pagesIn":0,"pagesOut":0,"pagesCached":0,"pagesSplitInternal":0,"pagesSplitLeaf":0,"readLocks":0,"writeLocks":0,"getRows":0,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0.076}]}`,
		output[2])
}
