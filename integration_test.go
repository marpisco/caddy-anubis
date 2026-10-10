package caddyanubis

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
)

const (
	httpPort          = 9080
	passChallengePath = "/.within.website/x/cmd/anubis/api/pass-challenge"
	browserUserAgent  = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
)

const globalOptions = `{
	skip_install_trust
	persist_config off
	admin localhost:2999
	http_port 9080
	https_port 9443
	grace_period 1ns
}
`

var challengeRe = regexp.MustCompile(`(?s)<script id="anubis_challenge"[^>]*>(.*?)</script>`)

// startCaddy runs a real Caddy with the given site blocks.
func startCaddy(t *testing.T, sites ...string) {
	t.Helper()
	caddytest.NewTester(t).InitServer(globalOptions+strings.Join(sites, "\n"), "caddyfile")
}

// writePolicy writes a policy that allows paths matching openRegex without a
// challenge and challenges everything else. It returns the file path.
func writePolicy(t *testing.T, openRegex string) string {
	t.Helper()
	policy := fmt.Sprintf(`bots:
  - name: open
    path_regex: %q
    action: ALLOW
  - name: everything-else
    path_regex: ".*"
    action: CHALLENGE
    challenge:
      algorithm: fast
      difficulty: 1
dnsbl: false
`, openRegex)
	file := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(file, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	return filepath.ToSlash(file)
}

// protectedSite is a site with init_anubis plus an anubis handler in front of
// a site-specific response.
func protectedSite(host, policyFile, body string) string {
	return fmt.Sprintf(`http://%s:%d {
	init_anubis {
		policy_file %q
	}
	handle {
		anubis
		respond %q
	}
}
`, host, httpPort, policyFile, body)
}

func siteURL(host, path string) string {
	return fmt.Sprintf("http://%s:%d%s", host, httpPort, path)
}

type page struct {
	status int
	header http.Header
	body   string
}

func (p page) isChallenge() bool {
	return challengeRe.MatchString(p.body)
}

// browser is an HTTP client that behaves like a browser: it keeps cookies,
// does not follow redirects on its own and reaches Caddy on loopback no
// matter which host name is requested.
type browser struct {
	t      *testing.T
	client *http.Client
}

func newBrowser(t *testing.T) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &browser{t: t, client: &http.Client{
		Jar:     jar,
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", httpPort))
			},
		},
	}}
}

// get requests rawURL, optionally sending extra cookies.
func (b *browser) get(rawURL string, cookies ...*http.Cookie) page {
	b.t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		b.t.Fatal(err)
	}
	req.Header.Set("User-Agent", browserUserAgent)
	// Anubis randomly rejects clients that do not accept gzip.
	req.Header.Set("Accept-Encoding", "gzip")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()

	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			b.t.Fatalf("GET %s: %v", rawURL, err)
		}
		reader = gz
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		b.t.Fatalf("GET %s: reading body: %v", rawURL, err)
	}
	return page{status: resp.StatusCode, header: resp.Header, body: string(body)}
}

// cookiesFor returns the cookies the browser holds for rawURL.
func (b *browser) cookiesFor(rawURL string) []*http.Cookie {
	b.t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		b.t.Fatal(err)
	}
	return b.client.Jar.Cookies(u)
}

// passChallenge requests rawURL, solves the challenge it answers with the way
// the Anubis script does, and returns the page served after the redirect.
func (b *browser) passChallenge(rawURL string) page {
	b.t.Helper()
	p := b.get(rawURL)
	match := challengeRe.FindStringSubmatch(p.body)
	if match == nil {
		b.t.Fatalf("GET %s: want a challenge page, got status %d: %.200s", rawURL, p.status, p.body)
	}

	var data struct {
		Rules struct {
			Difficulty int `json:"difficulty"`
		} `json:"rules"`
		Challenge struct {
			ID         string `json:"id"`
			RandomData string `json:"randomData"`
		} `json:"challenge"`
	}
	if err := json.Unmarshal([]byte(match[1]), &data); err != nil {
		b.t.Fatalf("GET %s: bad challenge data: %v", rawURL, err)
	}

	zeros := strings.Repeat("0", data.Rules.Difficulty)
	nonce := 0
	hash := ""
	for ; ; nonce++ {
		sum := sha256.Sum256([]byte(data.Challenge.RandomData + strconv.Itoa(nonce)))
		hash = hex.EncodeToString(sum[:])
		if strings.HasPrefix(hash, zeros) {
			break
		}
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		b.t.Fatal(err)
	}
	query := url.Values{
		"id":          {data.Challenge.ID},
		"response":    {hash},
		"nonce":       {strconv.Itoa(nonce)},
		"redir":       {rawURL},
		"elapsedTime": {"1"},
	}
	passed := b.get(u.Scheme + "://" + u.Host + passChallengePath + "?" + query.Encode())
	if passed.status != http.StatusFound {
		b.t.Fatalf("pass-challenge for %s: want 302, got %d: %.200s", rawURL, passed.status, passed.body)
	}
	return b.get(passed.header.Get("Location"))
}

func assertBody(t *testing.T, p page, want string) {
	t.Helper()
	if p.status != http.StatusOK || p.body != want {
		t.Errorf("got status %d body %.100q, want 200 %q", p.status, p.body, want)
	}
}

func assertChallenged(t *testing.T, p page) {
	t.Helper()
	if !p.isChallenge() {
		t.Errorf("got status %d body %.100q, want a challenge page", p.status, p.body)
	}
}

func TestTwoSitesUseTheirOwnPolicy(t *testing.T) {
	orders := map[string][]string{
		"a then b": {"a", "b"},
		"b then a": {"b", "a"},
	}
	for name, order := range orders {
		t.Run(name, func(t *testing.T) {
			policies := map[string]string{
				"a": writePolicy(t, `^/open-a`),
				"b": writePolicy(t, `^/open-b`),
			}
			var sites []string
			for _, id := range order {
				sites = append(sites, protectedSite(id+".localhost", policies[id], "site-"+id))
			}
			startCaddy(t, sites...)

			visitor := newBrowser(t)
			assertBody(t, visitor.get(siteURL("a.localhost", "/open-a")), "site-a")
			assertChallenged(t, visitor.get(siteURL("b.localhost", "/open-a")))
			assertBody(t, visitor.get(siteURL("b.localhost", "/open-b")), "site-b")
			assertChallenged(t, visitor.get(siteURL("a.localhost", "/open-b")))

			for _, id := range []string{"a", "b"} {
				assertBody(t, visitor.passChallenge(siteURL(id+".localhost", "/page")), "site-"+id)
				assertBody(t, visitor.get(siteURL(id+".localhost", "/page")), "site-"+id)
			}
		})
	}
}

func TestChallengeCookieOfOneSiteDoesNotUnlockAnother(t *testing.T) {
	startCaddy(t,
		protectedSite("a.localhost", writePolicy(t, `^/open-a`), "site-a"),
		protectedSite("b.localhost", writePolicy(t, `^/open-b`), "site-b"),
	)

	visitor := newBrowser(t)
	assertBody(t, visitor.passChallenge(siteURL("a.localhost", "/page")), "site-a")
	cookies := visitor.cookiesFor(siteURL("a.localhost", "/page"))
	if len(cookies) == 0 {
		t.Fatal("no cookie after passing the challenge on site a")
	}

	assertBody(t, newBrowser(t).get(siteURL("a.localhost", "/page"), cookies...), "site-a")
	assertChallenged(t, newBrowser(t).get(siteURL("b.localhost", "/page"), cookies...))
}

func TestPathScopedAnubisUnderInitAnubis(t *testing.T) {
	startCaddy(t, fmt.Sprintf(`http://admin.localhost:%d {
	init_anubis {
		policy_file %q
	}
	handle /admin/* {
		anubis
		respond "admin-body"
	}
	handle {
		respond "public-body"
	}
}
`, httpPort, writePolicy(t, `^/nothing-is-open`)))

	visitor := newBrowser(t)
	assertBody(t, visitor.get(siteURL("admin.localhost", "/")), "public-body")

	challenge := visitor.get(siteURL("admin.localhost", "/admin/x"))
	assertChallenged(t, challenge)
	asset := regexp.MustCompile(`src="(/\.within\.website/[^"]+)"`).FindStringSubmatch(challenge.body)
	if asset == nil {
		t.Fatal("challenge page references no /.within.website/ asset")
	}
	if got := visitor.get(siteURL("admin.localhost", asset[1])); got.status != http.StatusOK {
		t.Errorf("asset %s: status %d, want 200", asset[1], got.status)
	}

	assertBody(t, visitor.passChallenge(siteURL("admin.localhost", "/admin/x")), "admin-body")
}

func TestStandaloneAnubisChallenges(t *testing.T) {
	startCaddy(t, fmt.Sprintf(`http://solo.localhost:%d {
	handle {
		anubis {
			policy_file %q
		}
		respond "solo-body"
	}
}
`, httpPort, writePolicy(t, `^/nothing-is-open`)))

	visitor := newBrowser(t)
	assertChallenged(t, visitor.get(siteURL("solo.localhost", "/page")))
	assertBody(t, visitor.passChallenge(siteURL("solo.localhost", "/page")), "solo-body")
}

func TestSiteWithoutAnubisIsUntouched(t *testing.T) {
	startCaddy(t,
		protectedSite("a.localhost", writePolicy(t, `^/open-a`), "site-a"),
		fmt.Sprintf("http://plain.localhost:%d {\n\trespond \"plain-body\"\n}\n", httpPort),
	)

	visitor := newBrowser(t)
	assertBody(t, visitor.get(siteURL("plain.localhost", "/page")), "plain-body")
	assertBody(t, visitor.get(siteURL("plain.localhost", "/.within.website/x/cmd/anubis/static/js/main.mjs")), "plain-body")
	assertBody(t, visitor.get(siteURL("plain.localhost", "/robots.txt")), "plain-body")
}

func TestInitAnubisAnswers404ForUnknownAnubisPaths(t *testing.T) {
	startCaddy(t, protectedSite("a.localhost", writePolicy(t, `^/\.within\.website/missing`), "site-a"))

	got := newBrowser(t).get(siteURL("a.localhost", "/.within.website/missing"))
	if got.status != http.StatusNotFound {
		t.Errorf("status %d, want 404", got.status)
	}
}

func TestPolicyFileOnHandlerConflictsWithInitAnubis(t *testing.T) {
	policy := writePolicy(t, `^/open-a`)
	startCaddy(t, fmt.Sprintf(`http://conflict.localhost:%d {
	init_anubis
	handle {
		anubis {
			policy_file %q
		}
		respond "upstream-body"
	}
}
`, httpPort, policy))

	got := newBrowser(t).get(siteURL("conflict.localhost", "/open-a"))
	if got.status != http.StatusInternalServerError || strings.Contains(got.body, "upstream-body") {
		t.Errorf("got status %d body %.100q, want 500 without the upstream body", got.status, got.body)
	}
}

func TestTargetRedirectsWhenAllowed(t *testing.T) {
	const target = "https://example.com/"
	policy := writePolicy(t, `^/open-a`)

	layouts := map[string]string{
		"standalone": fmt.Sprintf(`http://t.localhost:%d {
	handle {
		anubis {
			target %s
			policy_file %q
		}
	}
}
`, httpPort, target, policy),
		"with init_anubis": fmt.Sprintf(`http://t.localhost:%d {
	init_anubis {
		policy_file %q
	}
	handle {
		anubis {
			target %s
		}
	}
}
`, httpPort, policy, target),
	}
	for name, caddyfile := range layouts {
		t.Run(name, func(t *testing.T) {
			startCaddy(t, caddyfile)

			got := newBrowser(t).get(siteURL("t.localhost", "/open-a"))
			if got.status != http.StatusTemporaryRedirect || got.header.Get("Location") != target {
				t.Errorf("got status %d Location %q, want 307 to %s", got.status, got.header.Get("Location"), target)
			}
		})
	}
}
