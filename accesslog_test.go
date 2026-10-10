package caddyanubis

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// bytespiderUserAgent matches a deny rule of the production policy, through
// the ai-catchall rule set.
const bytespiderUserAgent = "Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)"

// accessLogDirectives writes the access log of a site to logFile and logs the
// Anubis decision variables with it, as an operator configures them.
func accessLogDirectives(logFile string) string {
	return fmt.Sprintf(`	log {
		output file %q
		format json
	}
	log_append anubis_result {http.vars.anubis_result}
	log_append anubis_rule {http.vars.anubis_rule}
`, logFile)
}

// accessLogFile returns a new access log file path for the test. Its directory
// is not a t.TempDir: on Windows Caddy still holds the file open after the test
// (the config is only replaced by the next test), so removing it fails and
// t.TempDir would report that as a test failure. The removal is best effort.
func accessLogFile(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "accesslog")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return filepath.ToSlash(filepath.Join(dir, "access.log"))
}

// accessLogLine is the part of a JSON access log line the tests check. A
// RawMessage is empty when its field is missing from the line.
type accessLogLine struct {
	Request struct {
		URI string `json:"uri"`
	} `json:"request"`
	Result json.RawMessage `json:"anubis_result"`
	Rule   json.RawMessage `json:"anubis_rule"`
}

// decision returns the logged string, or "" when the field is null or missing.
func decision(raw json.RawMessage) string {
	var s string
	_ = json.Unmarshal(raw, &s)
	return s
}

// unset reports whether a logged field is missing or null.
func unset(raw json.RawMessage) bool {
	return len(raw) == 0 || string(raw) == "null"
}

// parseAccessLog returns the complete lines of the access log in file. A
// missing file has no lines yet.
func parseAccessLog(file string) ([]accessLogLine, error) {
	data, err := os.ReadFile(file)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// The last element is empty, or a line Caddy is still writing.
	parts := strings.Split(string(data), "\n")
	var lines []accessLogLine
	for _, part := range parts[:len(parts)-1] {
		var line accessLogLine
		if err := json.Unmarshal([]byte(part), &line); err != nil {
			return nil, fmt.Errorf("access log line %q: %w", part, err)
		}
		lines = append(lines, line)
	}
	return lines, nil
}

// readAccessLog waits until the access log in file has at least n lines and
// returns them.
func readAccessLog(t *testing.T, file string, n int) []accessLogLine {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		lines, err := parseAccessLog(file)
		if err != nil {
			t.Fatal(err)
		}
		if len(lines) >= n {
			return lines
		}
		if time.Now().After(deadline) {
			t.Fatalf("access log %s has %d lines, want %d", file, len(lines), n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// checkDecision fails the test unless line logged the result and the rule.
func checkDecision(t *testing.T, line accessLogLine, result, rule string) {
	t.Helper()
	if got := decision(line.Result); got != result {
		t.Errorf("anubis_result = %q, want %q", got, result)
	}
	if got := decision(line.Rule); got != rule {
		t.Errorf("anubis_rule = %q, want %q", got, rule)
	}
}

// checkUnset fails the test unless line has no Anubis decision.
func checkUnset(t *testing.T, line accessLogLine) {
	t.Helper()
	if !unset(line.Result) || !unset(line.Rule) {
		t.Errorf("anubis_result = %s, anubis_rule = %s, want both unset", line.Result, line.Rule)
	}
}

func TestAccessLogRecordsAllowedRequest(t *testing.T) {
	logFile := accessLogFile(t)
	startCaddy(t, protectedSiteWith("logallow.localhost", writePolicyFile(t, productionPolicy),
		accessLogDirectives(logFile), "upstream-body"))

	assertBody(t, newBrowser(t).get(siteURL("logallow.localhost", "/api/x")), "upstream-body")
	checkDecision(t, readAccessLog(t, logFile, 1)[0], "allow", "bot/api")
}

func TestAccessLogRecordsChallenge(t *testing.T) {
	logFile := accessLogFile(t)
	startCaddy(t, protectedSiteWith("logchallenge.localhost", writePolicyFile(t, productionPolicy),
		accessLogDirectives(logFile), "upstream-body"))

	assertChallenged(t, newBrowser(t).get(siteURL("logchallenge.localhost", "/page")))
	checkDecision(t, readAccessLog(t, logFile, 1)[0], "challenge", "bot/generic-browser")
}

func TestAccessLogRecordsPassAfterChallenge(t *testing.T) {
	logFile := accessLogFile(t)
	startCaddy(t, protectedSiteWith("logpass.localhost", writePolicyFile(t, productionPolicy),
		accessLogDirectives(logFile), "upstream-body"))

	// Solving the challenge makes three requests: the challenge page, the
	// pass-challenge call under /.within.website/, and the redirected page.
	assertBody(t, newBrowser(t).passChallenge(siteURL("logpass.localhost", "/page")), "upstream-body")
	lines := readAccessLog(t, logFile, 3)
	checkDecision(t, lines[0], "challenge", "bot/generic-browser")
	checkUnset(t, lines[1])
	checkDecision(t, lines[2], "pass", "bot/generic-browser")
}

func TestAccessLogRecordsDeny(t *testing.T) {
	logFile := accessLogFile(t)
	startCaddy(t, protectedSiteWith("logdeny.localhost", writePolicyFile(t, productionPolicy),
		accessLogDirectives(logFile), "upstream-body"))

	headers := http.Header{}
	headers.Set("User-Agent", bytespiderUserAgent)
	if got := newBrowser(t).getWith(siteURL("logdeny.localhost", "/page"), headers); got.body == "upstream-body" {
		t.Error("denied client reached the upstream")
	}
	checkDecision(t, readAccessLog(t, logFile, 1)[0], "deny", "bot/ai-catchall")
}

func TestAccessLogRecordsStandaloneDecisions(t *testing.T) {
	logFile := accessLogFile(t)
	startCaddy(t, fmt.Sprintf(`http://logsolo.localhost:%d {
%s	handle {
		anubis {
			policy_file %q
		}
		respond "solo-body"
	}
}
`, httpPort, accessLogDirectives(logFile), writePolicyFile(t, productionPolicy)))

	visitor := newBrowser(t)
	assertBody(t, visitor.get(siteURL("logsolo.localhost", "/api/x")), "solo-body")
	assertChallenged(t, visitor.get(siteURL("logsolo.localhost", "/page")))
	lines := readAccessLog(t, logFile, 2)
	checkDecision(t, lines[0], "allow", "bot/api")
	checkDecision(t, lines[1], "challenge", "bot/generic-browser")
}

// TestAccessLogIgnoresForgedAnubisHeaders checks that headers a client sends
// with Anubis' names do not change the logged decision or reach the upstream
// as if Anubis had set them.
func TestAccessLogIgnoresForgedAnubisHeaders(t *testing.T) {
	forged := http.Header{}
	forged.Set("X-Anubis-Action", "ALLOW")
	forged.Set("X-Anubis-Status", "PASS")
	forged.Set("X-Anubis-Rule", "forged")

	t.Run("challenged request", func(t *testing.T) {
		logFile := accessLogFile(t)
		startCaddy(t, protectedSiteWith("forged.localhost", writePolicyFile(t, productionPolicy),
			accessLogDirectives(logFile), "upstream-body"))

		assertChallenged(t, newBrowser(t).getWith(siteURL("forged.localhost", "/page"), forged))
		checkDecision(t, readAccessLog(t, logFile, 1)[0], "challenge", "bot/generic-browser")
	})

	t.Run("allowed request reaches upstream", func(t *testing.T) {
		startCaddy(t, protectedSite("echo.localhost", writePolicyFile(t, productionPolicy),
			"{http.request.header.X-Anubis-Rule}|{http.request.header.X-Anubis-Action}|{http.request.header.X-Anubis-Status}"))

		assertBody(t, newBrowser(t).getWith(siteURL("echo.localhost", "/api/x"), forged), "bot/api|ALLOW|")
	})
}

func TestAccessLogOfAnubisAssetIsUnset(t *testing.T) {
	logFile := accessLogFile(t)
	startCaddy(t, protectedSiteWith("logasset.localhost", writePolicyFile(t, productionPolicy),
		accessLogDirectives(logFile), "upstream-body"))

	newBrowser(t).get(siteURL("logasset.localhost", "/.within.website/x/cmd/anubis/static/js/main.mjs"))
	checkUnset(t, readAccessLog(t, logFile, 1)[0])
}

func TestAccessLogOfSiteWithoutAnubisIsUnset(t *testing.T) {
	protectedLog := accessLogFile(t)
	plainLog := accessLogFile(t)
	startCaddy(t,
		protectedSiteWith("logprotected.localhost", writePolicyFile(t, productionPolicy),
			accessLogDirectives(protectedLog), "upstream-body"),
		fmt.Sprintf(`http://logplain.localhost:%d {
%s	respond "plain-body"
}
`, httpPort, accessLogDirectives(plainLog)))

	assertBody(t, newBrowser(t).get(siteURL("logplain.localhost", "/page")), "plain-body")
	checkUnset(t, readAccessLog(t, plainLog, 1)[0])
}
