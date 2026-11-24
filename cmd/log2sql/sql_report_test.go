package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bvinc/go-sqlite-lite/sqlite3"
)

func TestSQLReportRateLimitErrors(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}
	if err := exec.Command(bash, "-c", `[[ ${BASH_VERSINFO[0]} -ge 4 ]]`).Run(); err != nil {
		t.Skip("sql_report.sh requires bash 4 or newer")
	}
	if _, err := exec.LookPath("sqlite3"); err != nil {
		t.Skip("sqlite3 CLI is not installed")
	}
	script, err := filepath.Abs("sql_report.sh")
	if err != nil {
		t.Fatal(err)
	}

	for _, scenario := range []string{"missing", "empty", "populated"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			db, err := sqlite3.Open(filepath.Join(dir, "sample.db"))
			if err != nil {
				t.Fatal(err)
			}
			var header bytes.Buffer
			writeHeader(&header)
			if err := db.Exec(header.String()); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "missing":
				err = db.Exec("DROP TABLE rateLimitErrors;")
			case "populated":
				err = db.Exec(`INSERT INTO rateLimitErrors (lineNumber,errorType,user,cmd) VALUES
					(1,'rate_limit','alice','user-sync'),
					(2,'rate_limit','alice','user-sync'),
					(3,'rate_limit',NULL,NULL),
					(4,'rate_limit','',''),
					(5,'max_cost','bob','user-fstat');`)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			args := []string{script, "-q", "-f", "json", "sample.db"}
			cmd := exec.Command(bash, args...)
			cmd.Dir = dir
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("report failed: %v\n%s", err, output)
			}
			data, err := os.ReadFile(filepath.Join(dir, "sample_report.json"))
			if err != nil {
				t.Fatal(err)
			}
			var report struct {
				Report struct {
					Sections map[string]map[string]struct {
						Results []map[string]interface{} `json:"results"`
					} `json:"sections"`
				} `json:"report"`
			}
			if err := json.Unmarshal(data, &report); err != nil {
				t.Fatalf("invalid JSON report: %v", err)
			}
			events := report.Report.Sections["events"]
			totals, exists := events["events_rate_limit_totals"]
			if scenario != "populated" {
				if exists {
					t.Fatal("rate-limit queries should be omitted")
				}
				return
			}
			if !exists || len(totals.Results) != 2 ||
				totals.Results[0]["errorType"] != "rate_limit" || totals.Results[0]["errors"] != float64(4) ||
				totals.Results[1]["errorType"] != "max_cost" || totals.Results[1]["errors"] != float64(1) {
				t.Fatalf("unexpected totals: %#v", totals.Results)
			}
			for _, name := range []string{"events_rate_limit_users", "events_rate_limit_commands"} {
				results := events[name].Results
				if len(results) != 3 || results[0]["errors"] != float64(2) || results[1]["errors"] != float64(2) {
					t.Fatalf("unexpected %s: %#v", name, results)
				}
				dimension := "user"
				if name == "events_rate_limit_commands" {
					dimension = "cmd"
				}
				if results[0]["errorType"] != "rate_limit" || results[0][dimension] != "(unknown)" {
					t.Fatalf("missing combined unknown %s: %#v", dimension, results)
				}
			}

			cmd = exec.Command(bash, script, "-q", "-s", "events", "-f", "json", "-t", "limit=1", "sample.db")
			cmd.Dir = dir
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("limited report failed: %v\n%s", err, output)
			}
			data, err = os.ReadFile(filepath.Join(dir, "sample_report.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
			events = report.Report.Sections["events"]
			if len(events["events_rate_limit_totals"].Results) != 2 ||
				len(events["events_rate_limit_users"].Results) != 1 ||
				len(events["events_rate_limit_commands"].Results) != 1 {
				t.Fatalf("top limit not applied correctly: %#v", events)
			}

			for _, format := range []string{"text", "csv", "html"} {
				cmd = exec.Command(bash, script, "-q", "-s", "events", "-f", format, "-t", "limit=1", "sample.db")
				cmd.Dir = dir
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("%s report failed: %v\n%s", format, err, output)
				}
				ext := format
				if format == "text" {
					ext = "txt"
				}
				data, err := os.ReadFile(filepath.Join(dir, "sample_report."+ext))
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(data), "Rate-limit errors by type and user (top 1)") ||
					!strings.Contains(string(data), "(unknown)") {
					t.Fatalf("%s report missing rate-limit summary", format)
				}
			}
		})
	}
}
