package caddyanubis

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/TecharoHQ/anubis/lib/config"
	"github.com/TecharoHQ/anubis/lib/policy"
)

// testLogger returns a logger with the decision handler around a text handler
// that writes to buf at the given level.
func testLogger(buf *bytes.Buffer, level slog.Level) *slog.Logger {
	inner := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: level})
	return slog.New(decisionHandler{inner: inner})
}

func TestDecisionHandlerCapturesCheckResult(t *testing.T) {
	var buf bytes.Buffer
	dec := &requestDecision{}
	ctx := context.WithValue(context.Background(), decisionCtxKey{}, dec)

	lg := testLogger(&buf, slog.LevelInfo).With("check_result", policy.CheckResult{Name: "bot/x", Rule: config.RuleDeny})
	lg.InfoContext(ctx, "explicit deny")

	rule, action := dec.get()
	if rule != "bot/x" || action != string(config.RuleDeny) {
		t.Errorf("decision = %q, %q, want bot/x, DENY", rule, action)
	}
}

func TestDecisionHandlerKeepsCheckResultThroughMoreWith(t *testing.T) {
	var buf bytes.Buffer
	dec := &requestDecision{}
	ctx := context.WithValue(context.Background(), decisionCtxKey{}, dec)

	lg := testLogger(&buf, slog.LevelInfo).
		With("check_result", policy.CheckResult{Name: "bot/y", Rule: config.RuleChallenge}).
		With("other", 1).WithGroup("g")
	lg.InfoContext(ctx, "msg")

	if rule, action := dec.get(); rule != "bot/y" || action != string(config.RuleChallenge) {
		t.Errorf("decision = %q, %q, want bot/y, CHALLENGE", rule, action)
	}
}

func TestDecisionHandlerEnablesDebugOnlyWithHolder(t *testing.T) {
	var buf bytes.Buffer
	lg := testLogger(&buf, slog.LevelInfo)

	if lg.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("debug enabled without a holder")
	}
	ctx := context.WithValue(context.Background(), decisionCtxKey{}, &requestDecision{})
	if !lg.Enabled(ctx, slog.LevelDebug) {
		t.Error("debug not enabled with a holder")
	}
}

func TestDecisionHandlerForwardsOnlyWhatInnerWants(t *testing.T) {
	var buf bytes.Buffer
	dec := &requestDecision{}
	ctx := context.WithValue(context.Background(), decisionCtxKey{}, dec)
	lg := testLogger(&buf, slog.LevelInfo).With("check_result", policy.CheckResult{Name: "bot/z", Rule: config.RuleChallenge})

	lg.DebugContext(ctx, "quiet debug")
	if buf.Len() != 0 {
		t.Errorf("debug record reached the inner handler: %q", buf.String())
	}
	if _, action := dec.get(); action == "" {
		t.Error("debug record did not reach the holder")
	}

	lg.InfoContext(ctx, "loud info")
	if !strings.Contains(buf.String(), "loud info") {
		t.Errorf("info record missing from inner output: %q", buf.String())
	}
}

func TestDecisionHandlerWithoutHolderIsPassThrough(t *testing.T) {
	var buf bytes.Buffer
	lg := testLogger(&buf, slog.LevelInfo).With("check_result", policy.CheckResult{Name: "bot/z", Rule: config.RuleAllow})

	lg.DebugContext(context.Background(), "dropped")
	lg.InfoContext(context.Background(), "kept")

	out := buf.String()
	if strings.Contains(out, "dropped") || !strings.Contains(out, "kept") {
		t.Errorf("output = %q, want only the info record", out)
	}
}
