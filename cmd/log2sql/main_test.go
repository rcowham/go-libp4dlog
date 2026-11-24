package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/bvinc/go-sqlite-lite/sqlite3"
	p4dlog "github.com/rcowham/go-libp4dlog"
	"github.com/sirupsen/logrus"
)

func TestRateLimitEventSQL(t *testing.T) {
	events := []p4dlog.RateLimitEvent{
		{LineNo: 10, EventTime: time.Date(2026, 11, 24, 7, 13, 44, 0, time.UTC), Pid: 42,
			ErrorType: p4dlog.RateLimitRefusal, User: "o'brien", Cmd: "user-info", ProcessKey: "key", ProcessLineNo: 2},
		{LineNo: 20, ErrorType: p4dlog.MaxCostExceeded, Cmd: "user-sync"},
	}
	for _, prepared := range []bool{false, true} {
		name := "sql"
		if prepared {
			name = "prepared"
		}
		t.Run(name, func(t *testing.T) {
			db, err := sqlite3.Open(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var sql bytes.Buffer
			writeHeader(&sql)
			if err := db.Exec(sql.String()); err != nil {
				t.Fatal(err)
			}
			if prepared {
				stmt, err := db.Prepare(getRateLimitErrorsStatement())
				if err != nil {
					t.Fatal(err)
				}
				defer stmt.Close()
				for i := range events {
					preparedInsertRateLimitEvent(logrus.New(), stmt, &events[i])
				}
			} else {
				sql.Reset()
				for i := range events {
					writeSQLRateLimitEvent(&sql, &events[i])
				}
				if err := db.Exec(sql.String()); err != nil {
					t.Fatal(err)
				}
			}
			stmt, err := db.Prepare(`SELECT COUNT(*) FROM rateLimitErrors WHERE
				(lineNumber=10 AND errorType='rate_limit' AND eventTime='2026/11/24 07:13:44'
				AND pid=42 AND user='o''brien' AND cmd='user-info' AND processkey='key' AND processLineNumber=2)
				OR (lineNumber=20 AND errorType='max_cost' AND eventTime IS NULL AND pid IS NULL
				AND user IS NULL AND cmd='user-sync' AND processkey IS NULL AND processLineNumber IS NULL)`)
			if err != nil {
				t.Fatal(err)
			}
			defer stmt.Close()
			ok, err := stmt.Step()
			if err != nil || !ok {
				t.Fatalf("query failed: %v", err)
			}
			var count int64
			if err := stmt.Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 2 {
				t.Fatalf("expected 2 matching rows, got %d", count)
			}
		})
	}
}
