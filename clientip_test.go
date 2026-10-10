package caddyanubis

import (
	"fmt"
	"net/http"
	"testing"
)

// trustedProxyServers makes the test Caddy trust the loopback peer as a proxy
// and read the client address from CF-Connecting-IP, as production does with
// Cloudflare.
const trustedProxyServers = `	servers {
		trusted_proxies static 127.0.0.1/32
		trusted_proxies_strict
		client_ip_headers CF-Connecting-IP
	}
`

// cloudflareHeaders returns the request headers for a client at clientIP
// reaching Caddy through Cloudflare.
func cloudflareHeaders(clientIP string) http.Header {
	headers := http.Header{}
	headers.Set("CF-Connecting-IP", clientIP)
	return headers
}

// writeAllowNetworkPolicy writes a policy that allows clients in cidr and
// challenges everything else.
func writeAllowNetworkPolicy(t *testing.T, cidr string) string {
	t.Helper()
	return writePolicyFile(t, fmt.Sprintf("bots:\n  - name: allowed-network\n    remote_addresses: [%q]\n    action: ALLOW\n%sdnsbl: false\n", cidr, challengeEverything))
}

func TestTrustedProxyClientIPComesFromCFConnectingIP(t *testing.T) {
	policy := writeAllowNetworkPolicy(t, "203.0.113.0/24")
	startCaddyWithGlobal(t, trustedProxyServers,
		protectedSite("proxied.localhost", policy, "{http.request.header.X-Real-IP}"))

	visitor := newBrowser(t)
	assertBody(t, visitor.getWith(siteURL("proxied.localhost", "/page"), cloudflareHeaders("203.0.113.7")), "203.0.113.7")
	assertChallenged(t, visitor.getWith(siteURL("proxied.localhost", "/page"), cloudflareHeaders("198.51.100.9")))
}

func TestForgedClientIPHeadersIgnoredWithoutTrustedProxy(t *testing.T) {
	policy := writeAllowNetworkPolicy(t, "203.0.113.0/24")
	startCaddy(t, protectedSite("direct.localhost", policy, "upstream-body"))

	forged := map[string]string{
		"CF-Connecting-IP": "203.0.113.7",
		"X-Real-IP":        "203.0.113.7",
		"X-Forwarded-For":  "203.0.113.7",
	}
	for name, value := range forged {
		t.Run(name, func(t *testing.T) {
			headers := http.Header{}
			headers.Set(name, value)
			assertChallenged(t, newBrowser(t).getWith(siteURL("direct.localhost", "/page"), headers))
		})
	}
}

func TestClientIPOverwritesForgedXRealIP(t *testing.T) {
	policy := writeAllowNetworkPolicy(t, "127.0.0.0/8")
	startCaddy(t, protectedSite("loopback.localhost", policy, "{http.request.header.X-Real-IP}"))

	headers := http.Header{}
	headers.Set("X-Real-IP", "203.0.113.7")
	assertBody(t, newBrowser(t).getWith(siteURL("loopback.localhost", "/page"), headers), "127.0.0.1")
}
