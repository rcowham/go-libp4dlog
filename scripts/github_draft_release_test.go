package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDraftRelease(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	remote := filepath.Join(dir, "remote.git")
	bin := filepath.Join(dir, "bin")
	for _, path := range []string{repo, bin, filepath.Join(repo, "scripts"), filepath.Join(repo, "cmd", "log2sql")} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	script, err := os.ReadFile("github_draft_release.sh")
	if err != nil {
		t.Fatal(err)
	}
	write := func(path, contents string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(contents), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(repo, "scripts", "github_draft_release.sh"), string(script), 0755)
	write(filepath.Join(repo, "cmd", "log2sql", "sql_report.sh"), "#!/bin/sh\n", 0755)
	write(filepath.Join(bin, "make"), `#!/usr/bin/env bash
set -eu
component=${2##*/}
mkdir -p "$2/bin"
for platform in darwin-amd64 darwin-arm64 linux-amd64 linux-arm64 windows-amd64.exe; do
    printf 'binary' | gzip > "$2/bin/$component-$platform.gz"
done
if [[ "$component" == p4locks || "$component" == p4dpending ]]; then
    printf 'binary' | gzip > "$2/bin/$component-windows-arm64.exe.gz"
fi
printf '%s\n' "$*" >> "$MAKE_LOG"
`, 0755)
	write(filepath.Join(bin, "gh"), `#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >> "$GH_LOG"
case "$1 $2" in
    "auth status") exit 0 ;;
    "release view")
        case "${GH_MODE:-missing}" in
            missing) echo 'release not found' >&2; exit 1 ;;
            error) echo 'network failure' >&2; exit 1 ;;
            published) echo false ;;
            draft) if [[ "$*" == *targetCommitish* ]]; then echo master; else echo true; fi ;;
        esac ;;
    "release create"|"release upload") exit 0 ;;
    *) exit 1 ;;
esac
`, 0755)
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, output)
		}
	}
	runGit("init", "-q", "--initial-branch=master")
	runGit("config", "user.name", "Test")
	runGit("config", "user.email", "test@example.invalid")
	runGit("add", "scripts/github_draft_release.sh", "cmd/log2sql/sql_report.sh")
	runGit("commit", "-qm", "Test fixture\n\nCo-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>")
	runGit("init", "-q", "--bare", remote)
	runGit("remote", "add", "origin", remote)
	runGit("push", "-q", "origin", "master")

	ghLog := filepath.Join(dir, "gh.log")
	makeLog := filepath.Join(dir, "make.log")
	run := func(mode string, args ...string) (string, error) {
		t.Helper()
		cmd := exec.Command("bash", append([]string{"scripts/github_draft_release.sh"}, args...)...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
			"GH_LOG="+ghLog, "MAKE_LOG="+makeLog, "GH_MODE="+mode)
		output, err := cmd.CombinedOutput()
		return string(output), err
	}
	read := func(path string) string {
		t.Helper()
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			return ""
		}
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}

	output, err := run("missing", "v1.2.3", "--dry-run")
	if err != nil || !strings.Contains(output, "Dry run:") {
		t.Fatalf("dry run failed: %v\n%s", err, output)
	}
	if read(ghLog) != "" || strings.Count(read(makeLog), "VERSION=v1.2.3 dist") != 4 ||
		!strings.Contains(output, "cmd/p4dpending/bin/p4dpending-windows-arm64.exe.gz") ||
		!strings.Contains(output, "cmd/log2sql/sql_report.sh") {
		t.Fatal("dry run did not build and list the expected assets")
	}

	output, err = run("missing", "v1.2.3", "--skip-build")
	if err != nil || !strings.Contains(read(ghLog), "release create v1.2.3") {
		t.Fatalf("draft creation failed: %v\n%s", err, output)
	}
	output, err = run("draft", "v1.2.3", "--skip-build")
	if err != nil || !strings.Contains(read(ghLog), "release upload v1.2.3") {
		t.Fatalf("draft update failed: %v\n%s", err, output)
	}
	for _, mode := range []string{"published", "error"} {
		before := read(ghLog)
		output, err = run(mode, "v1.2.3", "--skip-build")
		added := strings.TrimPrefix(read(ghLog), before)
		if err == nil || strings.Contains(added, "release create") || strings.Contains(added, "release upload") {
			t.Fatalf("%s release should fail without an upload: %v\n%s", mode, err, output)
		}
	}
	runGit("tag", "v1.2.4")
	runGit("push", "-q", "origin", "v1.2.4")
	runGit("commit", "--allow-empty", "-qm", "Next fixture\n\nCo-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>")
	runGit("push", "-q", "origin", "master")
	runGit("tag", "-d", "v1.2.4")
	output, err = run("missing", "v1.2.4", "--skip-build")
	if err == nil || !strings.Contains(output, "Remote tag v1.2.4 does not point at HEAD") {
		t.Fatalf("mismatched remote tag should fail: %v\n%s", err, output)
	}
	write(filepath.Join(repo, "cmd", "log2sql", "bin", "log2sql-linux-amd64.gz"), "not gzip", 0644)
	output, err = run("missing", "v1.2.5", "--skip-build", "--dry-run")
	if err == nil || !strings.Contains(output, "Invalid gzip release asset") {
		t.Fatalf("invalid asset should fail: %v\n%s", err, output)
	}
}
