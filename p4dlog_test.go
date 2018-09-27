package p4dlog

import (
	"bufio"
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
	inchan := make(chan []byte)
	fp := NewP4dFileParser(inchan, outchan)
	opts.testInput = `
Perforce server info:
	2015/09/02 15:23:09 pid 1616 robert@robert-test 127.0.0.1 [Microsoft Visual Studio 2013/12.0.21005.1] 'user-sync //...'
Perforce server info:
	2015/09/02 15:23:09 pid 1616 compute end .031s
Perforce server info:
	2015/09/02 15:23:09 pid 1616 completed .031s`
	go fp.P4LogParseFile(*opts)
	output := getResult(outchan)
	assert.Equal(t, `{"processKey":"4d4e5096f7b732e4ce95230ef085bf51","cmd":"user-sync","pid":1616,"lineNo":1,"user":"robert","workspace":"robert-test","computeLapse":"0.031","completedLapse":"0.031","ip":"127.0.0.1","app":"Microsoft Visual Studio 2013/12.0.21005.1","args":"//...","startTime":"2015/09/02 15:23:09","endTime":"2015/09/02 15:23:09"}`,
		output[0])

	// Sames as above with invalid Unicode strings
	inchan = make(chan []byte)
	outchan = make(chan string)
	fp = NewP4dFileParser(inchan, outchan)
	opts.testInput = `Perforce server info:
	2015/09/02 15:23:09 pid 1616 robert@robert-test 127.0.0.1 [Microsoft® Visual Studio® 2013/12.0.21005.1] 'user-sync //...'
Perforce server info:
	2015/09/02 15:23:09 pid 1616 compute end .031s
Perforce server info:
	2015/09/02 15:23:09 pid 1616 completed .031s`
	go fp.P4LogParseFile(*opts)
	output = getResult(outchan)
	assert.Equal(t, `{"processKey":"1f360d628fb2c9fe5354b8cf5022f7bd","cmd":"user-sync","pid":1616,"lineNo":1,"user":"robert","workspace":"robert-test","computeLapse":"0.031","completedLapse":"0.031","ip":"127.0.0.1","app":"Microsoft® Visual Studio® 2013/12.0.21005.1","args":"//...","startTime":"2015/09/02 15:23:09","endTime":"2015/09/02 15:23:09"}`,
		output[0])

}

func TestLogParseSwarm(t *testing.T) {
	opts := new(P4dParseOptions)
	inchan := make(chan []byte)
	outchan := make(chan string)
	fp := NewP4dFileParser(inchan, outchan)
	opts.testInput = `
Perforce server info:
	2016/12/21 08:39:39 pid 14769 perforce@~tmp.1482305462.13038.585a2fb6041cc1.60954329 192.168.18.31 [SWARM/2016.2/1446446] 'user-counter -u swarm-activity-fffec3dd {"type":"change","link":["change",{"change":1005814}],"user":"sahaltran05","action":"committed","target":"change 1005814","preposition":"into","description":"Mac address filtering and fixing the naming collision for the SSH and telnet libraries\n","details":null,"topic":"changes\/1005814","depotFile":null,"time":1482305978,"behalfOf":null,"projects":{"sah-automation":["sah-tests"]},"streams":["user-sahaltran05","personal-sahaltran05","project-sah-automation","group-p4altran","group-sah_app","group-sah_commun_modules","group-sah_components","group-sah_demo","group-sah_hardco","group-sah_nanterre","group-sah_nanterre_opensource","group-sah_opensource","group-sah_stbconfig","group-sah_stbconfig_dev","group-sah_system","group-sah_third_party","group-sah_validation","group-sah_wijgmaal","personal-sah4011"],"change":1005814}'
Perforce server info:
	2016/12/21 08:39:39 pid 14769 completed .003s 4+0us 0+16io 0+0net 6432k 0pf
	`
	go fp.P4LogParseFile(*opts)
	output := getResult(outchan)
	assert.Equal(t, `{"processKey":"d0ae06fd40d95180ca403a9c30084a66","cmd":"user-counter","pid":14769,"lineNo":1,"user":"perforce","workspace":"~tmp.1482305462.13038.585a2fb6041cc1.60954329","computeLapse":"","completedLapse":"0.003","ip":"192.168.18.31","app":"SWARM/2016.2/1446446","args":"-u swarm-activity-fffec3dd","startTime":"2016/12/21 08:39:39","endTime":"2016/12/21 08:39:39"}`,
		output[0])
}

func TestLogParseGitFusion(t *testing.T) {
	opts := new(P4dParseOptions)
	inchan := make(chan []byte)
	outchan := make(chan string)
	fp := NewP4dFileParser(inchan, outchan)
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
	go fp.P4LogParseFile(*opts)
	output := getResult(outchan)
	assert.Equal(t, `{"processKey":"1eec998ae9cc1ce44058f4503a01f2c0","cmd":"user-key","pid":10664,"lineNo":1,"user":"git-fusion-user","workspace":"GF-TRIGGER-567d67de-962","computeLapse":"","completedLapse":"0.844","ip":"10.100.104.199","app":"p4/2016.1/NTX64/1396108","args":"git-fusion-reviews-common-lock-owner","startTime":"2016/10/19 12:01:08","endTime":"2016/10/19 12:01:09"}`,
		output[0])
}

func TestLogParseMulti(t *testing.T) {
	opts := new(P4dParseOptions)
	inchan := make(chan []byte)
	outchan := make(chan string)
	fp := NewP4dFileParser(inchan, outchan)
	opts.testInput = `
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
	go fp.P4LogParseFile(*opts)
	output := getResult(outchan)
	exp1 := `{"processKey":"f9a64670da4d77a44225be236974bc8b","cmd":"user-sync","pid":1616,"lineNo":1,"user":"robert","workspace":"robert-test","computeLapse":"0.031","completedLapse":"0.031","ip":"127.0.0.1","app":"p4/2016.2/LINUX26X86_64/1598668","args":"//...","startTime":"2015/09/02 15:23:09","endTime":"2015/09/02 15:23:09"}`
	exp2 := `{"processKey":"2908cdb35e4b82dae3d0b403ef0c3bbf","cmd":"user-sync","pid":1534,"lineNo":5,"user":"fred","workspace":"fred-test","computeLapse":"0.021","completedLapse":"0.041","ip":"127.0.0.1","app":"p4/2016.2/LINUX26X86_64/1598668","args":"//...","startTime":"2015/09/02 15:23:09","endTime":"2015/09/02 15:23:09"}`
	assert.Equal(t, 2, len(output))
	assert.Equal(t, exp1, output[0])
	assert.Equal(t, exp2, output[1])

	// Test the same results iteratively
	inchan = make(chan []byte, 100)
	outchan = make(chan string, 100)
	//linechan := make(chan struct{})

	fp = NewP4dFileParser(inchan, outchan)
	go fp.LogParser()

	scanner := bufio.NewScanner(strings.NewReader(opts.testInput))
	for scanner.Scan() {
		line := scanner.Bytes()
		inchan <- line
	}
	close(inchan)

	output = []string{}
	for {
		line, ok := <-outchan
		if ok {
			output = append(output, line)
		} else {
			break
		}
	}
	assert.Equal(t, 2, len(output))
	assert.Equal(t, exp1, output[0])
	assert.Equal(t, exp2, output[1])
}

func TestLogParseSubmit(t *testing.T) {
	opts := new(P4dParseOptions)
	inchan := make(chan []byte)
	outchan := make(chan string)
	fp := NewP4dFileParser(inchan, outchan)
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
	go fp.P4LogParseFile(*opts)
	output := getResult(outchan)
	assert.Equal(t, 3, len(output))
	assert.Equal(t, `{"processKey":"465f0a630b021d3c695e90924a757b75","cmd":"user-submit","pid":25568,"lineNo":1,"user":"fred","workspace":"lon_ws","computeLapse":"","completedLapse":"0.178","ip":"10.1.2.3","app":"p4/2016.2/LINUX26X86_64/1598668","args":"-i","startTime":"2018/06/10 23:30:06","endTime":"2018/06/10 23:30:07"}`,
		output[0])
	assert.Equal(t, `{"processKey":"78dbd54644e624a9c6f5c338a0864d2a","cmd":"dm-SubmitChange","pid":25568,"lineNo":6,"user":"fred","workspace":"lon_ws","computeLapse":"0.252","completedLapse":"1.38","ip":"10.1.2.3","app":"p4/2016.2/LINUX26X86_64/1598668","args":"","startTime":"2018/06/10 23:30:07","endTime":"2018/06/10 23:30:08"}`,
		output[1])
	assert.Equal(t, `{"processKey":"128e10d7fe570c2d2f5f7f03e1186827","cmd":"dm-CommitSubmit","pid":25568,"lineNo":14,"user":"fred","workspace":"lon_ws","computeLapse":"","completedLapse":"1.38","ip":"10.1.2.3","app":"p4/2016.2/LINUX26X86_64/1598668","args":"","startTime":"2018/06/10 23:30:08","endTime":"2018/06/10 23:30:09"}`,
		output[2])
}
