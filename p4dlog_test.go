package p4dlog

import (
	"bufio"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func getResult(output chan string) []string {
	lines := []string{}
	for line := range output {
		lines = append(lines, line)
	}
	return lines
}

func TestLogParse(t *testing.T) {
	opts := new(P4dParseOptions)
	outchan := make(chan string)
	fp := NewP4dFileParser()
	opts.testInput = `
Perforce server info:
	2015/09/02 15:23:09 pid 1616 robert@robert-test 127.0.0.1 [Microsoft Visual Studio 2013/12.0.21005.1] 'user-sync //...'
Perforce server info:
	2015/09/02 15:23:09 pid 1616 compute end .031s
Perforce server info:
	2015/09/02 15:23:09 pid 1616 completed .031s`
	go fp.P4LogParseFile(*opts, outchan)
	output := getResult(outchan)
	assert.Equal(t, `{"processKey":"4d4e5096f7b732e4ce95230ef085bf51","cmd":"user-sync","pid":1616,"lineNo":2,"user":"robert","workspace":"robert-test","computeLapse":0.031,"completedLapse":0.031,"ip":"127.0.0.1","app":"Microsoft Visual Studio 2013/12.0.21005.1","args":"//...","startTime":"2015/09/02 15:23:09","endTime":"2015/09/02 15:23:09","running":0,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"tables":[]}`,
		output[0])

	// Sames as above with invalid Unicode strings
	outchan = make(chan string)
	fp = NewP4dFileParser()
	opts.testInput = `
Perforce server info:
	2015/09/02 15:23:09 pid 1616 robert@robert-test 127.0.0.1 [Microsoft® Visual Studio® 2013/12.0.21005.1] 'user-sync //...'
Perforce server info:
	2015/09/02 15:23:09 pid 1616 compute end .031s
Perforce server info:
	2015/09/02 15:23:09 pid 1616 completed .031s`
	go fp.P4LogParseFile(*opts, outchan)
	output = getResult(outchan)
	assert.Equal(t, `{"processKey":"1f360d628fb2c9fe5354b8cf5022f7bd","cmd":"user-sync","pid":1616,"lineNo":2,"user":"robert","workspace":"robert-test","computeLapse":0.031,"completedLapse":0.031,"ip":"127.0.0.1","app":"Microsoft® Visual Studio® 2013/12.0.21005.1","args":"//...","startTime":"2015/09/02 15:23:09","endTime":"2015/09/02 15:23:09","running":0,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"tables":[]}`,
		output[0])

}

func TestLogParseSwarm(t *testing.T) {
	opts := new(P4dParseOptions)
	outchan := make(chan string)
	fp := NewP4dFileParser()
	opts.testInput = `
Perforce server info:
	2016/12/21 08:39:39 pid 14769 perforce@~tmp.1482305462.13038.585a2fb6041cc1.60954329 192.168.18.31 [SWARM/2016.2/1446446] 'user-counter -u swarm-activity-fffec3dd {"type":"change","link":["change",{"change":1005814}],"user":"sahaltran05","action":"committed","target":"change 1005814","preposition":"into","description":"Mac address filtering and fixing the naming collision for the SSH and telnet libraries\n","details":null,"topic":"changes\/1005814","depotFile":null,"time":1482305978,"behalfOf":null,"projects":{"sah-automation":["sah-tests"]},"streams":["user-sahaltran05","personal-sahaltran05","project-sah-automation","group-p4altran","group-sah_app","group-sah_commun_modules","group-sah_components","group-sah_demo","group-sah_hardco","group-sah_nanterre","group-sah_nanterre_opensource","group-sah_opensource","group-sah_stbconfig","group-sah_stbconfig_dev","group-sah_system","group-sah_third_party","group-sah_validation","group-sah_wijgmaal","personal-sah4011"],"change":1005814}'
Perforce server info:
	2016/12/21 08:39:39 pid 14769 completed .003s 4+0us 0+16io 0+0net 6432k 0pf
`
	go fp.P4LogParseFile(*opts, outchan)
	output := getResult(outchan)
	assert.Equal(t, `{"processKey":"d0ae06fd40d95180ca403a9c30084a66","cmd":"user-counter","pid":14769,"lineNo":2,"user":"perforce","workspace":"~tmp.1482305462.13038.585a2fb6041cc1.60954329","computeLapse":0,"completedLapse":0.003,"ip":"192.168.18.31","app":"SWARM/2016.2/1446446","args":"-u swarm-activity-fffec3dd","startTime":"2016/12/21 08:39:39","endTime":"2016/12/21 08:39:39","running":0,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"tables":[]}`,
		output[0])
}

func TestLogParseGitFusion(t *testing.T) {
	opts := new(P4dParseOptions)
	outchan := make(chan string)
	fp := NewP4dFileParser()
	opts.testInput = `
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
	go fp.P4LogParseFile(*opts, outchan)
	output := getResult(outchan)
	assert.Equal(t, 1, len(output))
	assert.Equal(t, `{"processKey":"1eec998ae9cc1ce44058f4503a01f2c0","cmd":"user-key","pid":10664,"lineNo":2,"user":"git-fusion-user","workspace":"GF-TRIGGER-567d67de-962","computeLapse":0,"completedLapse":0.844,"ip":"10.100.104.199","app":"p4/2016.1/NTX64/1396108","args":"git-fusion-reviews-common-lock-owner","startTime":"2016/10/19 12:01:08","endTime":"2016/10/19 12:01:09","running":1,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":2,"rpcMsgsOut":3,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":523588,"rpcHimarkRev":523588,"rpcSnd":0,"rpcRcv":0.015,"tables":[{"tableName":"group","pagesIn":7,"pagesOut":0,"pagesCached":6,"readLocks":1,"writeLocks":0,"getRows":0,"posRows":3,"scanRows":67,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":15,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"nameval","pagesIn":6,"pagesOut":4,"pagesCached":4,"readLocks":0,"writeLocks":1,"getRows":0,"posRows":0,"scanRows":0,"putRows":1,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":16,"totalWriteHeld":15,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"protect","pagesIn":282,"pagesOut":0,"pagesCached":96,"readLocks":1,"writeLocks":0,"getRows":0,"posRows":1,"scanRows":14495,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":641,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"trigger","pagesIn":21,"pagesOut":0,"pagesCached":20,"readLocks":1,"writeLocks":0,"getRows":0,"posRows":1,"scanRows":486,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":47,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"user","pagesIn":4,"pagesOut":0,"pagesCached":3,"readLocks":1,"writeLocks":0,"getRows":1,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":16,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0}]}`,
		output[0])
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
var multiExp1 = `{"processKey":"f9a64670da4d77a44225be236974bc8b","cmd":"user-sync","pid":1616,"lineNo":2,"user":"robert","workspace":"robert-test","computeLapse":0.031,"completedLapse":0.031,"ip":"127.0.0.1","app":"p4/2016.2/LINUX26X86_64/1598668","args":"//...","startTime":"2015/09/02 15:23:09","endTime":"2015/09/02 15:23:09","running":0,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"tables":[]}`
var multiExp2 = `{"processKey":"2908cdb35e4b82dae3d0b403ef0c3bbf","cmd":"user-sync","pid":1534,"lineNo":6,"user":"fred","workspace":"fred-test","computeLapse":0.021,"completedLapse":0.041,"ip":"127.0.0.1","app":"p4/2016.2/LINUX26X86_64/1598668","args":"//...","startTime":"2015/09/02 15:23:09","endTime":"2015/09/02 15:23:09","running":1,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"tables":[]}`

func TestLogParseMulti(t *testing.T) {
	opts := new(P4dParseOptions)
	outchan := make(chan string)
	fp := NewP4dFileParser()
	opts.testInput = multiInput
	go fp.P4LogParseFile(*opts, outchan)
	output := getResult(outchan)
	assert.Equal(t, 2, len(output))
	sort.Strings(output)
	assert.Equal(t, multiExp1, output[1])
	assert.Equal(t, multiExp2, output[0])
}

func TestLogParseMultiIncrementalJSON(t *testing.T) {
	// Test the same results iteratively
	opts := new(P4dParseOptions)
	opts.testInput = multiInput
	inchan := make(chan []byte, 100)
	outchan := make(chan string, 100)

	fp := NewP4dFileParser()
	go fp.LogParser(inchan, nil, outchan)

	scanner := bufio.NewScanner(strings.NewReader(opts.testInput))
	for scanner.Scan() {
		line := scanner.Bytes()
		inchan <- line
	}
	close(inchan)

	output := []string{}
	for line := range outchan {
		output = append(output, line)
	}
	assert.Equal(t, 2, len(output))
	sort.Strings(output)
	assert.Equal(t, multiExp1, output[1])
	assert.Equal(t, multiExp2, output[0])
}

func TestLogParseMultiIncrementalCmd(t *testing.T) {
	// Test the same results iteratively
	opts := new(P4dParseOptions)
	opts.testInput = multiInput
	inchan := make(chan []byte, 100)
	cmdchan := make(chan Command, 100)

	fp := NewP4dFileParser()
	go fp.LogParser(inchan, cmdchan, nil)

	scanner := bufio.NewScanner(strings.NewReader(opts.testInput))
	for scanner.Scan() {
		line := scanner.Bytes()
		inchan <- line
	}
	close(inchan)

	output := []Command{}
	for cmd := range cmdchan {
		output = append(output, cmd)
	}
	assert.Equal(t, 2, len(output))
	assert.Equal(t, "user-sync", string(output[0].Cmd))
	assert.Equal(t, "user-sync", string(output[1].Cmd))
}

// func TestLogParseResolve(t *testing.T) {
// 	opts := new(P4dParseOptions)
// 	outchan := make(chan string)
// 	fp := NewP4dFileParser()
// 	opts.testInput = `
// Perforce server info:
// 	2017/12/07 15:00:01 pid 145941 buildernorth@RSGEDIAB23 10.10.16.171/10.10.20.195 [RSG.Pipeline.Automation.ClientWorker/1.0.0.0] 'user-resolve -At -at -c 16730784 //rdr3/assets/processed/levels/rdr3/terrain/instance_placement/r_03__dynamic_instances.xml'
// Perforce server info:
// 	2017/12/07 15:00:01 pid 145941 completed .002s 2+0us 0+8io 0+0net 5228k 0pf
// Perforce server info:
// 	2017/12/07 15:00:01 pid 145941 buildernorth@RSGEDIAB23 10.10.16.171/10.10.20.195 [RSG.Pipeline.Automation.ClientWorker/1.0.0.0] 'user-resolve -At -at -c 16730784 //rdr3/assets/processed/levels/rdr3/terrain/instance_placement/r_03__dynamic_instances.xml'
// --- lapse .002s
// --- usage 2+0us 0+16io 0+0net 5228k 0pf
// --- rpc msgs/size in+out 0+1/0mb+0mb himarks 318788/2096452 snd/rcv .000s/.000s
// --- db.user
// ---   pages in+out+cached 1+0+3
// ---   locks read/write 1/0 rows get+pos+scan put+del 1+0+0 0+0
// --- db.group
// ---   pages in+out+cached 1+0+16
// ---   locks read/write 1/0 rows get+pos+scan put+del 0+20+39 0+0
// --- db.domain
// ---   pages in+out+cached 1+0+4
// ---   locks read/write 1/0 rows get+pos+scan put+del 1+0+0 0+0
// --- db.view
// ---   pages in+out+cached 1+0+6
// ---   locks read/write 1/0 rows get+pos+scan put+del 0+1+2 0+0
// --- db.resolve
// ---   pages in+out+cached 7+0+6
// ---   locks read/write 1/0 rows get+pos+scan put+del 0+1+1 0+0
// --- db.revsx
// ---   locks read/write 1/0 rows get+pos+scan put+del 0+0+0 0+0
// --- db.revsh
// ---   pages in+out+cached 1+0+1
// ---   locks read/write 1/0 rows get+pos+scan put+del 0+0+0 0+0
// --- db.rev
// ---   locks read/write 1/0 rows get+pos+scan put+del 0+0+0 0+0
// --- db.working
// ---   pages in+out+cached 1+0+14
// ---   locks read/write 1/0 rows get+pos+scan put+del 0+0+0 0+0
// --- db.protect
// ---   pages in+out+cached 1+0+13
// ---   locks read/write 1/0 rows get+pos+scan put+del 0+1+523 0+0
// ---   total lock wait+held read/write 0ms+1ms/0ms+0ms
// --- db.monitor
// ---   pages in+out+cached 2+4+4096
// ---   locks read/write 0/2 rows get+pos+scan put+del 0+0+0 2+0
// --- clients/RSGEDIAB23(W)
// ---   total lock wait+held read/write 0ms+0ms/0ms+1ms

// Perforce server info:
// 	2017/12/07 15:00:01 pid 144683 svcrsgsanvmbuilder@sanb-nvm05 10.0.16.190/10.0.20.199 [RSG.Pipeline.Automation.ServerHost/1.0.0.0] 'user-describe 16724735'
// Perforce server info:
// 	2017/12/07 15:00:01 pid 145941 buildernorth@RSGEDIAB23 10.10.16.171/10.10.20.195 [RSG.Pipeline.Automation.ClientWorker/1.0.0.0] 'user-resolve -At -at -c 16730784 //rdr3/assets/processed/levels/rdr3/terrain/instance_placement/r_03__static_instances.xml'
// Perforce server info:
// 	2017/12/07 15:00:01 pid 144683 completed .002s 2+0us 0+0io 0+0net 6040k 0pf
// `
// 	go fp.P4LogParseFile(*opts, outchan)
// 	output := getResult(outchan)
// 	assert.Equal(t, 3, len(output))
// 	assert.Equal(t, `{"processKey":"f124e2662a91085aec5093353a0a62dc","cmd":"user-resolve","pid":145941,"lineNo":2,"user":"buildernorth","workspace":"RSGEDIAB23","computeLapse":0,"completedLapse":0.002,"ip":"10.10.16.171/10.10.20.195","app":"RSG.Pipeline.Automation.ClientWorker/1.0.0.0","args":"-At -at -c 16730784 //rdr3/assets/processed/levels/rdr3/terrain/instance_placement/r_03__dynamic_instances.xml","startTime":"2017/12/07 15:00:01","endTime":"2017/12/07 15:00:01"}`,
// 		output[0])

// }

func TestLogParseSubmit(t *testing.T) {
	opts := new(P4dParseOptions)
	outchan := make(chan string)
	fp := NewP4dFileParser()
	opts.testInput = `
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
	go fp.P4LogParseFile(*opts, outchan)
	output := getResult(outchan)
	assert.Equal(t, 3, len(output))
	assert.Equal(t, `{"processKey":"465f0a630b021d3c695e90924a757b75","cmd":"user-submit","pid":25568,"lineNo":2,"user":"fred","workspace":"lon_ws","computeLapse":0,"completedLapse":0.178,"ip":"10.1.2.3","app":"p4/2016.2/LINUX26X86_64/1598668","args":"-i","startTime":"2018/06/10 23:30:06","endTime":"2018/06/10 23:30:07","running":0,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"tables":[]}`,
		output[0])
	assert.Equal(t, `{"processKey":"78dbd54644e624a9c6f5c338a0864d2a","cmd":"dm-SubmitChange","pid":25568,"lineNo":7,"user":"fred","workspace":"lon_ws","computeLapse":0.252,"completedLapse":1.38,"ip":"10.1.2.3","app":"p4/2016.2/LINUX26X86_64/1598668","args":"","startTime":"2018/06/10 23:30:07","endTime":"2018/06/10 23:30:08","running":1,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"tables":[]}`,
		output[1])
	assert.Equal(t, `{"processKey":"128e10d7fe570c2d2f5f7f03e1186827","cmd":"dm-CommitSubmit","pid":25568,"lineNo":15,"user":"fred","workspace":"lon_ws","computeLapse":0,"completedLapse":1.38,"ip":"10.1.2.3","app":"p4/2016.2/LINUX26X86_64/1598668","args":"","startTime":"2018/06/10 23:30:08","endTime":"2018/06/10 23:30:09","running":1,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":0,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":0,"rpcHimarkRev":0,"rpcSnd":0,"rpcRcv":0,"tables":[{"tableName":"","pagesIn":0,"pagesOut":0,"pagesCached":0,"readLocks":0,"writeLocks":0,"getRows":0,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":1367,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"archmap","pagesIn":0,"pagesOut":0,"pagesCached":0,"readLocks":0,"writeLocks":0,"getRows":0,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":780,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"integed","pagesIn":0,"pagesOut":0,"pagesCached":0,"readLocks":0,"writeLocks":0,"getRows":0,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":795,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0}]}`,
		output[2])
	// assert.Equal(t, `asdf`,
	// 	output[3])
}

func TestLogDuplicatePids(t *testing.T) {
	opts := new(P4dParseOptions)
	outchan := make(chan string)
	fp := NewP4dFileParser()
	opts.testInput = `
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
	go fp.P4LogParseFile(*opts, outchan)
	output := getResult(outchan)
	assert.Equal(t, 2, len(output))
	assert.Equal(t, `{"processKey":"9b2bf87ce1b8e88d0d89cf44cffc4a8c","cmd":"user-change","pid":4496,"lineNo":2,"user":"lcheng","workspace":"lcheng","computeLapse":0,"completedLapse":0.015,"ip":"10.100.72.195","app":"P4V/NTX64/2014.1/888424/v76","args":"-o","startTime":"2016/10/19 14:53:48","endTime":"2016/10/19 14:53:48","running":0,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":1,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":523588,"rpcHimarkRev":64836,"rpcSnd":0,"rpcRcv":0,"tables":[{"tableName":"group","pagesIn":1,"pagesOut":0,"pagesCached":7,"readLocks":1,"writeLocks":0,"getRows":0,"posRows":6,"scanRows":11,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"user","pagesIn":1,"pagesOut":0,"pagesCached":3,"readLocks":1,"writeLocks":0,"getRows":1,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0}]}`,
		output[0])
	assert.Equal(t, `{"processKey":"9b2bf87ce1b8e88d0d89cf44cffc4a8c.18","cmd":"user-change","pid":4496,"lineNo":18,"user":"lcheng","workspace":"lcheng","computeLapse":0,"completedLapse":0.016,"ip":"10.100.72.195","app":"P4V/NTX64/2014.1/888424/v76","args":"-o","startTime":"2016/10/19 14:53:48","endTime":"2016/10/19 14:53:48","running":0,"uCpu":0,"sCpu":0,"diskIn":0,"diskOut":0,"ipcIn":0,"ipcOut":0,"maxRss":0,"pageFaults":0,"rpcMsgsIn":0,"rpcMsgsOut":1,"rpcSizeIn":0,"rpcSizeOut":0,"rpcHimarkFwd":523588,"rpcHimarkRev":64836,"rpcSnd":0,"rpcRcv":0,"tables":[{"tableName":"group","pagesIn":1,"pagesOut":0,"pagesCached":7,"readLocks":1,"writeLocks":0,"getRows":0,"posRows":6,"scanRows":11,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"user","pagesIn":1,"pagesOut":0,"pagesCached":3,"readLocks":1,"writeLocks":0,"getRows":1,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0}]}`,
		output[1])
}

func TestLogTriggerEntries(t *testing.T) {
	opts := new(P4dParseOptions)
	outchan := make(chan string)
	fp := NewP4dFileParser()
	opts.testInput = `
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
---   locks read/write 0/2 rows get+pos+scan put+del 2+0+0 1+0
`
	go fp.P4LogParseFile(*opts, outchan)
	output := getResult(outchan)
	assert.Equal(t, 1, len(output))
	assert.Equal(t, `{"processKey":"25aeba7a5658170fea61117076fa00d5","cmd":"user-change","pid":148469,"lineNo":2,"user":"Fred","workspace":"LONWS","computeLapse":0,"completedLapse":0.413,"ip":"10.40.16.14/10.40.48.29","app":"3DSMax/1.0.0.0","args":"-i","startTime":"2017/12/07 15:00:21","endTime":"2017/12/07 15:00:21","running":0,"uCpu":10,"sCpu":11,"diskIn":12,"diskOut":13,"ipcIn":14,"ipcOut":15,"maxRss":4088,"pageFaults":22,"rpcMsgsIn":20,"rpcMsgsOut":21,"rpcSizeIn":22,"rpcSizeOut":23,"rpcHimarkFwd":318788,"rpcHimarkRev":318789,"rpcSnd":0.001,"rpcRcv":0.002,"tables":[{"tableName":"counters","pagesIn":6,"pagesOut":3,"pagesCached":2,"readLocks":0,"writeLocks":2,"getRows":2,"posRows":0,"scanRows":0,"putRows":1,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0},{"tableName":"trigger_swarm.changesave","pagesIn":0,"pagesOut":0,"pagesCached":0,"readLocks":0,"writeLocks":0,"getRows":0,"posRows":0,"scanRows":0,"putRows":0,"delRows":0,"totalReadWait":0,"totalReadHeld":0,"totalWriteWait":0,"totalWriteHeld":0,"maxReadWait":0,"maxReadHeld":0,"maxWriteWait":0,"maxWriteHeld":0,"peekCount":0,"totalPeekWait":0,"totalPeekHeld":0,"maxPeekWait":0,"maxPeekHeld":0,"triggerLapse":0.044}]}`,
		output[0])
}
