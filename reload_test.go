package caddyanubis

import (
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
