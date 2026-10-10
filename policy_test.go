package caddyanubis

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// productionPolicy is the policy shape the module runs with, built from
// Anubis' own rule sets. Only the generic browser rule challenges, so a client
// that matches no rule is not challenged.
const productionPolicy = `bots:
  - import: (data)/bots/_deny-pathological.yaml
  - import: (data)/meta/ai-block-aggressive.yaml
  - import: (data)/crawlers/_allow-good.yaml
  - import: (data)/common/keep-internet-working.yaml
  - name: api
    path_regex: ^/api/
    action: ALLOW
  - name: generic-browser
    user_agent_regex: Mozilla|Opera
    action: CHALLENGE
    challenge:
      algorithm: fast
      difficulty: 1
dnsbl: false
`

const googlebotUserAgent = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

func TestGooglebotIsAllowedByAddress(t *testing.T) {
	tests := []struct {
		name     string
		global   string
		clientIP string
		allowed  bool
	}{
		{name: "google address behind trusted proxy", global: trustedProxyServers, clientIP: "66.249.66.1", allowed: true},
		{name: "other address behind trusted proxy", global: trustedProxyServers, clientIP: "203.0.113.7"},
		{name: "forged google address without trusted proxy", clientIP: "66.249.66.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			startCaddyWithGlobal(t, tt.global,
				protectedSite("crawler.localhost", writePolicyFile(t, productionPolicy), "upstream-body"))

			headers := cloudflareHeaders(tt.clientIP)
			headers.Set("User-Agent", googlebotUserAgent)
			got := newBrowser(t).getWith(siteURL("crawler.localhost", "/page"), headers)
			if tt.allowed {
				assertBody(t, got, "upstream-body")
			} else {
				assertChallenged(t, got)
			}
		})
	}
}

func TestProgramPathsBypassChallengeByPolicy(t *testing.T) {
	tests := []struct {
		path          string
		wantChallenge bool
	}{
		{path: "/api/v1/health"},
		{path: "/.well-known/security.txt"},
		{path: "/robots.txt"},
		{path: "/favicon.ico"},
		{path: "/", wantChallenge: true},
		{path: "/page", wantChallenge: true},
	}

	startCaddy(t, protectedSite("programs.localhost", writePolicyFile(t, productionPolicy), "upstream-body"))
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := newBrowser(t).get(siteURL("programs.localhost", tt.path))
			if tt.wantChallenge {
				assertChallenged(t, got)
			} else {
				assertBody(t, got, "upstream-body")
			}
		})
	}
}

// TestNonBrowserClientIsNotChallengedByPolicy pins what the production policy
// does with a client that is not a browser: no rule matches curl, so it gets
// through the default threshold unchallenged.
func TestNonBrowserClientIsNotChallengedByPolicy(t *testing.T) {
	startCaddy(t, protectedSite("curl.localhost", writePolicyFile(t, productionPolicy), "upstream-body"))

	headers := http.Header{}
	headers.Set("User-Agent", "curl/8.5.0")
	assertBody(t, newBrowser(t).getWith(siteURL("curl.localhost", "/page"), headers), "upstream-body")
}

func TestCaddyfileRoutesBypassChallenge(t *testing.T) {
	policy := writePolicy(t, `^/nothing-is-open`)
	startCaddy(t, fmt.Sprintf(`http://routes.localhost:%d {
	init_anubis {
		policy_file %q
	}
	handle /api/* {
		respond "api-body"
	}
	handle /.well-known/* {
		respond "wk-body"
	}
	handle {
		anubis
		respond "site-body"
	}
}
`, httpPort, policy))

	visitor := newBrowser(t)
	assertBody(t, visitor.get(siteURL("routes.localhost", "/api/x")), "api-body")
	assertBody(t, visitor.get(siteURL("routes.localhost", "/.well-known/x")), "wk-body")
	assertChallenged(t, visitor.get(siteURL("routes.localhost", "/page")))
}

func TestNewServerRejectsBrokenPolicyFile(t *testing.T) {
	tests := []struct {
		name string
		file string
	}{
		{name: "missing file", file: filepath.Join(t.TempDir(), "missing.yaml")},
		{name: "unknown action", file: writePolicyFile(t, "bots:\n  - name: bad\n    path_regex: .*\n    action: BOGUS\ndnsbl: false\n")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()

			opts := anubisOptions{PolicyFile: tt.file}
			if _, err := opts.newServer(ctx); err == nil {
				t.Error("newServer returned nil error, want error")
			}
		})
	}
}

// TestBrokenPolicyReloadKeepsOldConfig checks that a reload with a broken
// policy file is refused and the site keeps answering with its old policy.
func TestBrokenPolicyReloadKeepsOldConfig(t *testing.T) {
	tests := []struct {
		name string
		file string
	}{
		{name: "missing file", file: filepath.Join(t.TempDir(), "missing.yaml")},
		{name: "unknown action", file: writePolicyFile(t, "bots:\n  - name: bad\n    path_regex: .*\n    action: BOGUS\ndnsbl: false\n")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			startCaddy(t, protectedSite("reload.localhost", writePolicy(t, `^/open-a`), "site-good"))

			status, body := postCaddyfile(t, buildCaddyfile("", protectedSite("reload.localhost", tt.file, "site-broken")))
			if status == http.StatusOK || !strings.Contains(body, "can't parse policy file") {
				t.Errorf("reload status %d body %.200s, want it refused for the broken policy file", status, body)
			}

			assertBody(t, newBrowser(t).get(siteURL("reload.localhost", "/open-a")), "site-good")
		})
	}
}

// postCaddyfile loads text into the test Caddy through its admin API and
// returns the response status and body.
func postCaddyfile(t *testing.T, text string) (int, string) {
	t.Helper()
	resp, err := http.Post(adminURL+"/load", "text/caddyfile", strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}
