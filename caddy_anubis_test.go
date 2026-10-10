package caddyanubis

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

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
