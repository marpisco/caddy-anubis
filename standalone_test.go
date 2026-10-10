package caddyanubis

import (
	"fmt"
	"sync"
	"testing"
)

// bareStandaloneSite is a site whose anubis handler has no options and no
// init_anubis, so it builds its server on the first request.
func bareStandaloneSite(host string) string {
	return fmt.Sprintf(`http://%s:%d {
	handle {
		anubis
		respond "bare-body"
	}
}
`, host, httpPort)
}

func TestBareStandaloneAnubisChallenges(t *testing.T) {
	startCaddy(t, bareStandaloneSite("bare.localhost"))

	visitor := newBrowser(t)
	assertChallenged(t, visitor.get(siteURL("bare.localhost", "/page")))
	assertBody(t, visitor.passChallenge(siteURL("bare.localhost", "/page")), "bare-body")
}

func TestBareStandaloneAnubisServesConcurrentFirstRequests(t *testing.T) {
	startCaddy(t, bareStandaloneSite("burst.localhost"))

	const requests = 20
	pages := make([]page, requests)
	var wg sync.WaitGroup
	for i := range pages {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pages[i] = newBrowser(t).get(siteURL("burst.localhost", "/page"))
		}()
	}
	wg.Wait()

	for i, p := range pages {
		if !p.isChallenge() {
			t.Errorf("request %d: got status %d body %.100q, want a challenge page", i, p.status, p.body)
		}
	}
}
