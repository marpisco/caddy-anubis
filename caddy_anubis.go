package caddyanubis

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

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
	PolicyFile string `json:"policy_file,omitempty"`
}

// unmarshalOption parses the Caddyfile option the dispenser is on.
func (o *anubisOptions) unmarshalOption(d *caddyfile.Dispenser) error {
	switch d.Val() {
	case "policy_file":
		if !d.NextArg() {
			return d.ArgErr()
		}
		o.PolicyFile = d.Val()
	default:
		return d.Errf("unrecognized option: %s", d.Val())
	}
	return nil
}

// newServer loads the policy and builds an Anubis server with its own signing
// key and challenge store.
func (o *anubisOptions) newServer(ctx caddy.Context, logger *zap.Logger) (*libanubis.Server, error) {
	pol, err := libanubis.LoadPoliciesOrDefault(ctx, o.PolicyFile, anubis.DefaultDifficulty, "info", false)
	if err != nil {
		return nil, err
	}

	return libanubis.New(libanubis.Options{
		Next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			down, ok := r.Context().Value(downstreamCtxKey{}).(*downstream)
			if !ok || down.next == nil {
				http.NotFound(w, r)
				return
			}
			if err := down.next.ServeHTTP(w, r); err != nil {
				logger.Error("downstream handler error", zap.Error(err))
			}
		}),
		Policy:           pol,
		ServeRobotsTXT:   true,
		CookieExpiration: anubis.CookieDefaultExpirationTime,
	})
}

// serveAnubis lets srv handle r. The next handler is what runs when Anubis
// allows the request.
func serveAnubis(srv *libanubis.Server, w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) {
	setAnubisClientIP(r)
	ctx := context.WithValue(r.Context(), downstreamCtxKey{}, &downstream{next: next})
	srv.ServeHTTP(w, r.WithContext(ctx))
}

// AnubisMiddleware is a Caddy middleware that integrates Anubis proof-of-work
// challenges to protect upstream resources from scraper bots and AI crawlers.
// When the site has init_anubis it uses the site's Anubis server and policy;
// otherwise it uses a server of its own.
type AnubisMiddleware struct {
	anubisOptions

	Target *string `json:"target,omitempty"`

	anubisServer *libanubis.Server
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

	// Built even if init_anubis ends up serving requests, so that a broken
	// policy file fails the config load.
	srv, err := m.newServer(ctx, m.logger)
	if err != nil {
		return err
	}
	m.anubisServer = srv
	m.logger.Info("anubis middleware provisioned")
	return nil
}

func (m *AnubisMiddleware) Validate() error { return nil }

func (m *AnubisMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	srv := m.anubisServer
	if siteServer, ok := caddyhttp.GetVar(r.Context(), siteServerVarKey).(*libanubis.Server); ok {
		if m.PolicyFile != "" {
			return caddyhttp.Error(http.StatusInternalServerError,
				errors.New("anubis: policy_file is set on the anubis handler but the site has init_anubis; set policy_file on init_anubis instead"))
		}
		srv = siteServer
	}

	if m.Target != nil {
		next = caddyhttp.HandlerFunc(m.redirectToTarget)
	}
	serveAnubis(srv, w, r, next)
	return nil
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

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "target":
			if !d.NextArg() {
				return d.ArgErr()
			}
			val := d.Val()
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

	srv, err := m.newServer(ctx, m.logger)
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
		serveAnubis(m.anubisServer, w, r, nil)
		return nil
	}

	caddyhttp.SetVar(r.Context(), siteServerVarKey, m.anubisServer)
	return next.ServeHTTP(w, r)
}

func (m *initAnubisMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

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
