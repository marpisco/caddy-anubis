package caddyanubis

import (
	"context"
	"net/http/httptest"
	"testing"

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
