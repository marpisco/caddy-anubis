package caddyanubis

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestSetAnubisClientIPUsesCaddyClientIP(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "192.0.2.10:1234"
	req.Header.Set("X-Real-IP", "192.0.2.99")

	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{
		caddyhttp.ClientIPVarKey: "203.0.113.7",
	})
	req = req.WithContext(ctx)

	setAnubisClientIP(req)

	if got, want := req.Header.Get("X-Real-IP"), "203.0.113.7"; got != want {
		t.Errorf("X-Real-IP = %q, want %q", got, want)
	}
}

func TestSetAnubisClientIPFallsBackToRemoteAddress(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "[2001:db8::1]:1234"

	setAnubisClientIP(req)

	if got, want := req.Header.Get("X-Real-IP"), "2001:db8::1"; got != want {
		t.Errorf("X-Real-IP = %q, want %q", got, want)
	}
}

func adaptCaddyfile(t *testing.T, caddyfileText string) ([]byte, error) {
	t.Helper()
	adapter := caddyconfig.GetAdapter("caddyfile")
	if adapter == nil {
		t.Fatal("caddyfile adapter not registered")
	}
	out, _, err := adapter.Adapt([]byte(caddyfileText), nil)
	return out, err
}

func TestAdaptRejectsInvalidCaddyfile(t *testing.T) {
	tests := []struct {
		name       string
		caddyfile  string
		wantSubstr string
	}{
		{
			name: "anubis unknown option",
			caddyfile: `:9080 {
	handle {
		anubis {
			polcy_file /tmp/x.yaml
		}
		respond "ok"
	}
}`,
			wantSubstr: "polcy_file",
		},
		{
			name: "anubis policy_file without argument",
			caddyfile: `:9080 {
	handle {
		anubis {
			policy_file
		}
		respond "ok"
	}
}`,
			wantSubstr: "policy_file",
		},
		{
			name: "anubis target without argument",
			caddyfile: `:9080 {
	handle {
		anubis {
			target
		}
		respond "ok"
	}
}`,
			wantSubstr: "target",
		},
		{
			name: "init_anubis policy_file without argument",
			caddyfile: `:9080 {
	init_anubis {
		policy_file
	}
}`,
			wantSubstr: "policy_file",
		},
		{
			name: "init_anubis unknown option",
			caddyfile: `:9080 {
	init_anubis {
		bogus x
	}
}`,
			wantSubstr: "bogus",
		},
		{
			name: "anubis serve_robots_txt with argument",
			caddyfile: `:9080 {
	handle {
		anubis {
			serve_robots_txt yes
		}
		respond "ok"
	}
}`,
			wantSubstr: "yes",
		},
		{
			name: "anubis cookie_domain without argument",
			caddyfile: `:9080 {
	handle {
		anubis {
			cookie_domain
		}
		respond "ok"
	}
}`,
			wantSubstr: "cookie_domain",
		},
		{
			name: "anubis cookie_domain with extra argument",
			caddyfile: `:9080 {
	handle {
		anubis {
			cookie_domain example.com extra
		}
		respond "ok"
	}
}`,
			wantSubstr: "wrong argument count",
		},
		{
			name: "init_anubis opengraph_target without argument",
			caddyfile: `:9080 {
	init_anubis {
		opengraph_target
	}
}`,
			wantSubstr: "opengraph_target",
		},
		{
			name: "init_anubis opengraph_target with extra argument",
			caddyfile: `:9080 {
	init_anubis {
		opengraph_target http://127.0.0.1:3000 extra
	}
}`,
			wantSubstr: "wrong argument count",
		},
		{
			name: "anubis target with extra argument",
			caddyfile: `:9080 {
	handle {
		anubis {
			target a b
		}
		respond "ok"
	}
}`,
			wantSubstr: "wrong argument count",
		},
		{
			name: "anubis argument on directive line in handle",
			caddyfile: `:9080 {
	handle {
		anubis foo
		respond "ok"
	}
}`,
			wantSubstr: "wrong argument count",
		},
		{
			name: "anubis argument on directive line at site level",
			caddyfile: `:9080 {
	anubis foo
	respond "ok"
}`,
			wantSubstr: "wrong argument count",
		},
		{
			name: "init_anubis argument on directive line",
			caddyfile: `:9080 {
	init_anubis foo
}`,
			wantSubstr: "wrong argument count",
		},
		{
			name: "init_anubis path matcher",
			caddyfile: `:9080 {
	init_anubis /path/*
}`,
			wantSubstr: "wrong argument count",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := adaptCaddyfile(t, tt.caddyfile)
			if err == nil {
				t.Fatal("Adapt returned nil error, want error")
			}
			if !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Errorf("error = %q, want it to mention %q", err, tt.wantSubstr)
			}
		})
	}
}

func TestInitAnubisUnmarshalRejectsPolicyFileWithoutArgument(t *testing.T) {
	var m initAnubisMiddleware
	d := caddyfile.NewTestDispenser("init_anubis {\n\tpolicy_file\n}")

	if err := m.UnmarshalCaddyfile(d); err == nil {
		t.Fatal("UnmarshalCaddyfile returned nil error, want error")
	}
}

func TestAdaptAcceptsValidAnubisOptions(t *testing.T) {
	caddyfileText := `:9080 {
	handle {
		anubis {
			target https://example.com
			policy_file /tmp/p.yaml
		}
		respond "ok"
	}
}`

	out, err := adaptCaddyfile(t, caddyfileText)
	if err != nil {
		t.Fatalf("Adapt returned error: %v", err)
	}

	for _, want := range []string{`"policy_file":"/tmp/p.yaml"`, `"target":"https://example.com"`} {
		if !strings.Contains(string(out), want) {
			t.Errorf("adapted JSON does not contain %s\n%s", want, out)
		}
	}
}

func TestAdaptAcceptsRequestMatcherOnAnubisDirective(t *testing.T) {
	tests := []struct {
		name      string
		caddyfile string
		want      string
	}{
		{
			name: "path matcher on the directive line",
			caddyfile: `:9080 {
	anubis /admin/*
	respond "ok"
}`,
			want: `"path":["/admin/*"]`,
		},
		{
			name: "named matcher on the directive line",
			caddyfile: `:9080 {
	@m path /x/*
	anubis @m
	respond "ok"
}`,
			want: `"path":["/x/*"]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := adaptCaddyfile(t, tt.caddyfile)
			if err != nil {
				t.Fatalf("Adapt returned error: %v", err)
			}
			if !strings.Contains(string(out), tt.want) {
				t.Errorf("adapted JSON does not contain %s\n%s", tt.want, out)
			}
		})
	}
}

func TestNewServerRequiresOpenGraphTarget(t *testing.T) {
	policy := writePolicyWith(t, `^/open`, openGraphPolicy)
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	opts := anubisOptions{PolicyFile: policy}
	if _, err := opts.newServer(ctx); err == nil || !strings.Contains(err.Error(), "opengraph_target") {
		t.Errorf("newServer error = %v, want one mentioning opengraph_target", err)
	}
}

func TestAdaptCookieDomainAndOpenGraphTarget(t *testing.T) {
	tests := []struct {
		name      string
		caddyfile string
		want      string
	}{
		{
			name: "anubis with cookie_domain",
			caddyfile: `:9080 {
	handle {
		anubis {
			cookie_domain example.com
		}
		respond "ok"
	}
}`,
			want: `"cookie_domain":"example.com"`,
		},
		{
			name: "init_anubis with opengraph_target",
			caddyfile: `:9080 {
	init_anubis {
		opengraph_target http://127.0.0.1:3000
	}
}`,
			want: `"opengraph_target":"http://127.0.0.1:3000"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := adaptCaddyfile(t, tt.caddyfile)
			if err != nil {
				t.Fatalf("Adapt returned error: %v", err)
			}
			if !strings.Contains(string(out), tt.want) {
				t.Errorf("adapted JSON does not contain %s\n%s", tt.want, out)
			}
		})
	}
}

func TestAdaptServeRobotsTXTOption(t *testing.T) {
	tests := []struct {
		name        string
		caddyfile   string
		want        string
		wantPresent bool
	}{
		{
			name: "anubis with serve_robots_txt",
			caddyfile: `:9080 {
	handle {
		anubis {
			serve_robots_txt
		}
		respond "ok"
	}
}`,
			want:        `"serve_robots_txt":true`,
			wantPresent: true,
		},
		{
			name: "init_anubis with serve_robots_txt",
			caddyfile: `:9080 {
	init_anubis {
		serve_robots_txt
	}
}`,
			want:        `"serve_robots_txt":true`,
			wantPresent: true,
		},
		{
			name: "anubis without serve_robots_txt",
			caddyfile: `:9080 {
	handle {
		anubis
		respond "ok"
	}
}`,
			want: `serve_robots_txt`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := adaptCaddyfile(t, tt.caddyfile)
			if err != nil {
				t.Fatalf("Adapt returned error: %v", err)
			}
			if got := strings.Contains(string(out), tt.want); got != tt.wantPresent {
				t.Errorf("adapted JSON contains %s = %t, want %t\n%s", tt.want, got, tt.wantPresent, out)
			}
		})
	}
}
