#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

required_commands=(git go npm gzip zstd brotli)
for cmd in "${required_commands[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "error: required command '$cmd' is not installed or not in PATH" >&2
        exit 1
    fi
done

if ! command -v xcaddy >/dev/null 2>&1; then
    echo "xcaddy not found, installing with 'go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest'..."
    (cd "$SCRIPT_DIR" && go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest)
fi

XCADDY_BIN="$(command -v xcaddy || true)"
if [ -z "$XCADDY_BIN" ]; then
    GOPATH_BIN="$(go env GOPATH)/bin/xcaddy"
    if [ -x "$GOPATH_BIN" ]; then
        XCADDY_BIN="$GOPATH_BIN"
    else
        echo "error: xcaddy was installed but could not be found in PATH or GOPATH/bin" >&2
        exit 1
    fi
fi

ANUBIS_VERSION="$(cd "$SCRIPT_DIR" && go list -m -f '{{.Version}}' github.com/TecharoHQ/anubis)"
ANUBIS_DIR="$(mktemp -d /tmp/caddy-anubis-anubis.XXXXXX)"

cleanup() {
    rm -rf "$ANUBIS_DIR"
}
trap cleanup EXIT

echo "Cloning Anubis $ANUBIS_VERSION into $ANUBIS_DIR..."
git clone --branch "$ANUBIS_VERSION" --depth 1 https://github.com/TecharoHQ/anubis.git "$ANUBIS_DIR"

echo "Generating Anubis assets..."
(
    cd "$ANUBIS_DIR"
    npm ci
    npm run assets
)

echo "Building Caddy with caddy-anubis plugin..."
(
    cd "$SCRIPT_DIR"
    "$XCADDY_BIN" build \
        --with github.com/marpisco/caddy-anubis=. \
        --replace github.com/TecharoHQ/anubis="$ANUBIS_DIR"
)

echo "Build complete: $SCRIPT_DIR/caddy"
echo "Run it with: $SCRIPT_DIR/caddy run --config $SCRIPT_DIR/Caddyfile"
