package caddyanubis

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/TecharoHQ/anubis"
	libanubis "github.com/TecharoHQ/anubis/lib"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

const (
	// anubisPathPrefix is where Anubis serves its assets and challenge API.
	anubisPathPrefix = "/.within.website/"

	// siteServerVarKey is the request variable init_anubis uses to publish
	// the site's Anubis server to the anubis handlers further down the chain.
	siteServerVarKey = "anubis.site_server"
)

// downstreamCtxKey is used to pass the handler that runs after Anubis allows a
// request through the request context. It lets one Anubis server serve
// several handlers.
type downstreamCtxKey struct{}

// downstream is what Anubis calls once it allows a request.
type downstream struct {
	next caddyhttp.Handler
	err  error
}

func init() {
	caddy.RegisterModule(AnubisMiddleware{})
	caddy.RegisterModule(initAnubisMiddleware{})
	httpcaddyfile.RegisterHandlerDirective("anubis", parseAnubis)
	httpcaddyfile.RegisterDirectiveOrder("anubis", httpcaddyfile.After, "invoke")
	httpcaddyfile.RegisterDirective("init_anubis", parseInitAnubis)
	httpcaddyfile.RegisterDirectiveOrder("init_anubis", httpcaddyfile.Before, "invoke")
}

// anubisOptions are the options shared by anubis and init_anubis.
type anubisOptions struct {
	PolicyFile               string `json:"policy_file,omitempty"`
	ServeRobotsTXT           bool   `json:"serve_robots_txt,omitempty"`
	CookieDomain             string `json:"cookie_domain,omitempty"`
	OpenGraphTarget          string `json:"opengraph_target,omitempty"`
	Ed25519PrivateKeyHexFile string `json:"ed25519_private_key_hex_file,omitempty"`
}

// unmarshalOption parses the Caddyfile option the dispenser is on.
func (o *anubisOptions) unmarshalOption(d *caddyfile.Dispenser) error {
	switch d.Val() {
	case "policy_file":
		val, err := singleArg(d)
		if err != nil {
			return err
		}
		o.PolicyFile = val
	case "serve_robots_txt":
		if d.NextArg() {
			return d.ArgErr()
		}
		o.ServeRobotsTXT = true
	case "cookie_domain":
		val, err := singleArg(d)
		if err != nil {
			return err
		}
		o.CookieDomain = val
	case "opengraph_target":
		val, err := singleArg(d)
		if err != nil {
			return err
		}
		o.OpenGraphTarget = val
	case "ed25519_private_key_hex_file":
		val, err := singleArg(d)
		if err != nil {
			return err
		}
		o.Ed25519PrivateKeyHexFile = val
	default:
		return d.Errf("unrecognized option: %s", d.Val())
	}
	return nil
}

// singleArg reads the one argument of the option the dispenser is on.
func singleArg(d *caddyfile.Dispenser) (string, error) {
	if !d.NextArg() {
		return "", d.ArgErr()
	}
	val := d.Val()
	if d.NextArg() {
		return "", d.ArgErr()
	}
	return val, nil
}

// newServer loads the policy and builds an Anubis server with its own signing
// key and challenge store.
func (o *anubisOptions) newServer(ctx caddy.Context) (*libanubis.Server, error) {
	pol, err := libanubis.LoadPoliciesOrDefault(ctx, o.PolicyFile, anubis.DefaultDifficulty, "info", false)
	if err != nil {
		return nil, err
	}

	// Without overrides Anubis fetches the real pages to read their tags, and
	// it needs an address to fetch them from.
	if pol.OpenGraph.Enabled && len(pol.OpenGraph.Override) == 0 && o.OpenGraphTarget == "" {
		return nil, errors.New("anubis: the policy enables openGraph, set opengraph_target to the address the pages can be fetched from")
	}

	// A nil key makes Anubis generate a new one, as it does without the option.
	var signingKey ed25519.PrivateKey
	if o.Ed25519PrivateKeyHexFile != "" {
		signingKey, err = loadSigningKey(o.Ed25519PrivateKeyHexFile)
		if err != nil {
			return nil, err
		}
	}

	return libanubis.New(libanubis.Options{
		Next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			down, ok := r.Context().Value(downstreamCtxKey{}).(*downstream)
			if !ok || down.next == nil {
				http.NotFound(w, r)
				return
			}
			down.err = down.next.ServeHTTP(w, r)
		}),
		ED25519PrivateKey: signingKey,
		Policy:            pol,
		OpenGraph:         pol.OpenGraph,
		Target:            o.OpenGraphTarget,
		CookieDomain:      o.CookieDomain,
		ServeRobotsTXT:    o.ServeRobotsTXT,
		CookieExpiration:  anubis.CookieDefaultExpirationTime,
	})
}

// loadSigningKey reads a hex-encoded ed25519 seed from path and builds the
// signing key from it. Its errors never include the file content.
func loadSigningKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("anubis: ed25519_private_key_hex_file %s: %w", path, err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("anubis: ed25519_private_key_hex_file %s: content is not hex-encoded", path)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("anubis: ed25519_private_key_hex_file %s: want a %d-byte seed, got %d bytes", path, ed25519.SeedSize, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// serveAnubis lets srv handle r. The next handler is what runs when Anubis
// allows the request. It returns the error of that handler, if any.
func serveAnubis(srv *libanubis.Server, w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	setAnubisClientIP(r)
	down := &downstream{next: next}
	ctx := context.WithValue(r.Context(), downstreamCtxKey{}, down)
	srv.ServeHTTP(w, r.WithContext(ctx))
	return down.err
}

// AnubisMiddleware is a Caddy middleware that integrates Anubis proof-of-work
// challenges to protect upstream resources from scraper bots and AI crawlers.
// When the site has init_anubis it uses the site's Anubis server and policy;
// otherwise it uses a server of its own.
type AnubisMiddleware struct {
	anubisOptions

	Target *string `json:"target,omitempty"`

	// anubisServer is the server of the handler itself. With options it is
	// built in Provision; without them, on the first request that needs it.
	anubisServer *libanubis.Server
	buildErr     error
	buildOnce    *sync.Once
	ctx          caddy.Context
	logger       *zap.Logger
}

func (AnubisMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.anubis",
		New: func() caddy.Module { return new(AnubisMiddleware) },
	}
}

func (m *AnubisMiddleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger().Named("anubis")
	m.ctx = ctx
	m.buildOnce = new(sync.Once)

	// Without options the handler uses the policy built into Anubis, so there
	// is nothing to check. Building a server loads a policy, which leaves a
	// goroutine behind for good, so it waits until a request needs the server.
	if m.anubisOptions != (anubisOptions{}) {
		// Built even if init_anubis ends up serving requests, so that a
		// broken policy file fails the config load.
		srv, err := m.newServer(ctx)
		if err != nil {
			return err
		}
		m.anubisServer = srv
	}
	m.logger.Info("anubis middleware provisioned")
	return nil
}

// ownServer returns the server of the handler itself, building it on first use
// if Provision did not. A failed build is not retried.
func (m *AnubisMiddleware) ownServer() (*libanubis.Server, error) {
	m.buildOnce.Do(func() {
		if m.anubisServer == nil {
			m.anubisServer, m.buildErr = m.newServer(m.ctx)
		}
	})
	return m.anubisServer, m.buildErr
}

func (m *AnubisMiddleware) Validate() error { return nil }

func (m *AnubisMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	srv, ok := caddyhttp.GetVar(r.Context(), siteServerVarKey).(*libanubis.Server)
	if ok && m.anubisOptions != (anubisOptions{}) {
		return caddyhttp.Error(http.StatusInternalServerError,
			errors.New("anubis: the site has init_anubis, so only target may be set on the anubis handler; set the other options on init_anubis instead"))
	}
	if !ok {
		var err error
		if srv, err = m.ownServer(); err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}
	}

	if m.Target != nil {
		next = caddyhttp.HandlerFunc(m.redirectToTarget)
	}
	return serveAnubis(srv, w, r, next)
}

// redirectToTarget sends the visitor to the configured target.
func (m *AnubisMiddleware) redirectToTarget(w http.ResponseWriter, r *http.Request) error {
	http.Redirect(w, r, *m.Target, http.StatusTemporaryRedirect)
	return nil
}

func setAnubisClientIP(r *http.Request) {
	clientIP, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	if clientIP == "" {
		var err error
		clientIP, _, err = net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			clientIP = r.RemoteAddr
		}
	}

	if net.ParseIP(clientIP) == nil {
		r.Header.Del("X-Real-IP")
		return
	}
	r.Header.Set("X-Real-IP", clientIP)
}

func (m *AnubisMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name
	// A request matcher on the directive line was already taken by the handler
	// directive wrapper, so any other argument here is a mistake.
	if d.NextArg() {
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "target":
			val, err := singleArg(d)
			if err != nil {
				return err
			}
			m.Target = &val
		default:
			if err := m.unmarshalOption(d); err != nil {
				return err
			}
		}
	}

	return nil
}

func parseAnubis(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m AnubisMiddleware
	if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return &m, nil
}

// initAnubisMiddleware is the Anubis server of a site. It serves the assets and
// the challenge API under /.within.website/ and publishes its server to the
// anubis handlers of the same site, so they all share one policy, key and
// challenge store. Place it once per site block, outside any handle block.
type initAnubisMiddleware struct {
	anubisOptions

	anubisServer *libanubis.Server
	logger       *zap.Logger
}

func (initAnubisMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.init_anubis",
		New: func() caddy.Module { return new(initAnubisMiddleware) },
	}
}

func (m *initAnubisMiddleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger().Named("init_anubis")

	srv, err := m.newServer(ctx)
	if err != nil {
		return err
	}
	m.anubisServer = srv
	m.logger.Info("init_anubis provisioned")
	return nil
}

func (initAnubisMiddleware) Validate() error { return nil }

func (m *initAnubisMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if strings.HasPrefix(r.URL.Path, anubisPathPrefix) {
		r.RequestURI = r.URL.RequestURI()
		return serveAnubis(m.anubisServer, w, r, nil)
	}

	caddyhttp.SetVar(r.Context(), siteServerVarKey, m.anubisServer)
	return next.ServeHTTP(w, r)
}

func (m *initAnubisMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name
	// init_anubis takes no request matcher, it must see every request of the site.
	if d.NextArg() {
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		if err := m.unmarshalOption(d); err != nil {
			return err
		}
	}

	return nil
}

func parseInitAnubis(h httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error) {
	var m initAnubisMiddleware
	if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}

	mod, _ := caddy.GetModule("http.handlers.init_anubis")
	var warnings []caddyconfig.Warning
	jsonObj := caddyconfig.JSONModuleObject(m, "handler", mod.ID.Name(), &warnings)

	// No matcher: the handler must see every request of the site to publish
	// its server to the anubis handlers.
	return []httpcaddyfile.ConfigValue{
		{
			Class: "route",
			Value: caddyhttp.Route{
				HandlersRaw: []json.RawMessage{jsonObj},
			},
		},
	}, nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*AnubisMiddleware)(nil)
	_ caddy.Validator             = (*AnubisMiddleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*AnubisMiddleware)(nil)
	_ caddyfile.Unmarshaler       = (*AnubisMiddleware)(nil)
	_ caddy.Provisioner           = (*initAnubisMiddleware)(nil)
	_ caddy.Validator             = (*initAnubisMiddleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*initAnubisMiddleware)(nil)
	_ caddyfile.Unmarshaler       = (*initAnubisMiddleware)(nil)
)
