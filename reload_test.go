package caddyanubis

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	reloadCount = 5

	// decayWorkerFrame is the stack frame of the cleanup goroutine of an
	// Anubis in-memory store. Upstream never stops it.
	decayWorkerFrame = "decaymap.(*Impl"
	decayWorkerFunc  = ").cleanupWorker"
)

// countGoroutines returns how many goroutines have a stack frame containing
// every one of parts.
func countGoroutines(parts ...string) int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}

	count := 0
	for _, stack := range strings.Split(string(buf), "\n\n") {
		matches := true
		for _, part := range parts {
			matches = matches && strings.Contains(stack, part)
		}
		if matches {
			count++
		}
	}
	return count
}

func countDecayWorkers() int {
	return countGoroutines(decayWorkerFrame, decayWorkerFunc)
}

// threeHandlersSite is a site with init_anubis and three bare anubis handlers.
func threeHandlersSite(body string) string {
	return fmt.Sprintf(`http://reload.localhost:%d {
	init_anubis
	handle /a/* {
		anubis
		respond "a-%[2]s"
	}
	handle /b/* {
		anubis
		respond "b-%[2]s"
	}
	handle {
		anubis
		respond "root-%[2]s"
	}
}
`, httpPort, body)
}

// TestReloadLeaksOnlyServersInUse counts the cleanup goroutines of Anubis
// stores across config reloads. Upstream never stops one per policy load, so
// the module must load a policy only for each server that serves requests.
func TestReloadLeaksOnlyServersInUse(t *testing.T) {
	startCaddy(t, threeHandlersSite("v0"))
	baseline := countDecayWorkers()

	for i := 1; i <= reloadCount; i++ {
		status, body := postCaddyfile(t, buildCaddyfile("", threeHandlersSite(fmt.Sprintf("v%d", i))))
		if status != http.StatusOK {
			t.Fatalf("reload %d: status %d body %.200s", i, status, body)
		}
	}
	// Caddy unloads the old configs in the background.
	time.Sleep(time.Second)

	grown := countDecayWorkers() - baseline
	t.Logf("cleanup workers: baseline %d, grew by %d over %d reloads", baseline, grown, reloadCount)
	if grown > reloadCount {
		t.Errorf("cleanup workers grew by %d over %d reloads, want at most %d (one per reload)", grown, reloadCount, reloadCount)
	}

	assertChallenged(t, newBrowser(t).get(siteURL("reload.localhost", "/a/x")))
}

// reloadSite is a site like protectedSite whose init_anubis also gets the extra
// option lines.
func reloadSite(host, policy, extra, body string) string {
	return fmt.Sprintf(`http://%s:%d {
	init_anubis {
		policy_file %q
		%s
	}
	handle {
		anubis
		respond %q
	}
}
`, host, httpPort, policy, extra, body)
}

// reloadTo loads the Caddyfile text and fails the test unless Caddy accepts it.
func reloadTo(t *testing.T, sites string) {
	t.Helper()
	status, body := postCaddyfile(t, buildCaddyfile("", sites))
	if status != http.StatusOK {
		t.Fatalf("reload: status %d body %.200s", status, body)
	}
}

// TestSigningKeyFileKeepsChallengePassAfterReload checks that a visitor who
// passed the challenge is let through after a reload when the signing key is
// read from a file, because the key, not the reload, decides the cookie.
func TestSigningKeyFileKeepsChallengePassAfterReload(t *testing.T) {
	policy := writePolicy(t, `^/nothing-is-open`)
	keyOption := fmt.Sprintf("ed25519_private_key_hex_file %q", writeKeyFile(t, hex.EncodeToString(newSeed(t))+"\n"))
	startCaddy(t, reloadSite("reload.localhost", policy, keyOption, "v1"))

	visitor := newBrowser(t)
	assertBody(t, visitor.passChallenge(siteURL("reload.localhost", "/page")), "v1")

	reloadTo(t, reloadSite("reload.localhost", policy, keyOption, "v2"))
	assertBody(t, visitor.get(siteURL("reload.localhost", "/page")), "v2")
}

// TestReloadChallengesAgainWithoutSigningKeyFile is the control for the test
// above: without the key file every reload makes a new key, so the visitor is
// challenged again.
func TestReloadChallengesAgainWithoutSigningKeyFile(t *testing.T) {
	policy := writePolicy(t, `^/nothing-is-open`)
	startCaddy(t, reloadSite("reload.localhost", policy, "", "v1"))

	visitor := newBrowser(t)
	assertBody(t, visitor.passChallenge(siteURL("reload.localhost", "/page")), "v1")

	reloadTo(t, reloadSite("reload.localhost", policy, "", "v2"))
	assertChallenged(t, visitor.get(siteURL("reload.localhost", "/page")))
}

// TestSharedSigningKeyAcceptsCookieOfAnotherSite pins what one key file shared
// by two sites does. Anubis checks the cookie signature and the rule that
// matched the request, not the site, so a cookie from site a also opens site b
// when both sites use the key and challenge with the same rule. Separate keys,
// the default, reject that cookie.
func TestSharedSigningKeyAcceptsCookieOfAnotherSite(t *testing.T) {
	keyOption := fmt.Sprintf("ed25519_private_key_hex_file %q", writeKeyFile(t, hex.EncodeToString(newSeed(t))+"\n"))
	policyA := writePolicy(t, `^/open-a`)
	tests := []struct {
		name    string
		policyB string
	}{
		{name: "same policy file", policyB: policyA},
		{name: "other policy file with the same rules", policyB: writePolicy(t, `^/open-b`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			startCaddy(t,
				reloadSite("site-a.localhost", policyA, keyOption, "site-a"),
				reloadSite("site-b.localhost", tt.policyB, keyOption, "site-b"))

			visitor := newBrowser(t)
			visitor.passChallenge(siteURL("site-a.localhost", "/page"))
			cookies := visitor.cookiesFor(siteURL("site-a.localhost", "/page"))
			assertBody(t, newBrowser(t).get(siteURL("site-b.localhost", "/page"), cookies...), "site-b")
		})
	}
}
