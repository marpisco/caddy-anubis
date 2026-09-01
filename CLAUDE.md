# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with codebase.

## Project Overview

This is a **Caddy HTTP server module** that integrates [Anubis](https://github.com/TecharoHQ/anubis) proof-of-work challenges to protect upstream resources from scraper bots and AI crawlers. It provides two Caddyfile directives:

- **`init_anubis`** - Server-level directive that provisions the global Anubis server and serves static assets at `/.within.website/`. Place once per server block.
- **`anubis`** - Handler-level middleware that can be used inside `handle` blocks to protect specific paths (root or subdirectory).

## Key Dependencies

- **Caddy v2** (`github.com/caddyserver/caddy/v2`) - The host server framework.
- **Anubis** (`github.com/TecharoHQ/anubis`) - The upstream proof-of-work challenge engine. Its Go module excludes generated browser assets, so builds clone the pinned tag and generate assets locally.

## Architecture

The entire plugin is a single Go file: `caddy_anubis.go`. Three middleware types:

- **`initAnubisMiddleware`** - Provisions the global Anubis server (with a stub `http.NotFound` next handler) and serves `/.within.website/*` routes. Registered via `RegisterDirective` so it creates its own route with path matching, independent of `handle` blocks.
- **`AnubisMiddleware`** - Creates its own Anubis server per-instance with the correct Caddy passthrough (via `context.WithValue`). Optionally stores itself as the global server if `init_anubis` hasn't run. Supports `target <url>` and `policy_file <path>`.
- **`anubisStaticMiddleware`** - Backward compatibility handler that delegates `/.within.website/` to the global Anubis server.

The global Anubis server is shared via `sync/atomic.Pointer[libanubis.Server]`.

### Caddyfile Example

```caddy
:8080 {
    init_anubis          # Global: provisions server + serves static assets

    handle /admin/* {
        anubis           # Path-scoped: protects /admin/ only
        respond "Admin area"
    }

    handle {
        anubis           # Root-scoped: protects all paths
        file_server { root web/ }
    }
}
```

## Build and Run

### Prerequisites

- Go 1.26.3 or newer
- Node.js 24 or newer with npm
- gzip, zstd, brotli, and xcaddy

### Build Caddy with Plugin

The standard `xcaddy build` needs a local upstream Anubis checkout because generated browser assets are not included in its Go module. Use the dependency version pinned in `go.mod`:

```bash
ANUBIS_DIR="$(mktemp -d)"
ANUBIS_VERSION="$(go list -m -f '{{.Version}}' github.com/TecharoHQ/anubis)"
git clone --branch "$ANUBIS_VERSION" --depth 1 https://github.com/TecharoHQ/anubis.git "$ANUBIS_DIR"

(
    cd "$ANUBIS_DIR"
    npm ci
    npm run assets
)

xcaddy build \
    --with github.com/marpisco/caddy-anubis=. \
    --replace github.com/TecharoHQ/anubis="$ANUBIS_DIR"
```

### Run with the Local Caddyfile

```bash
./caddy run --config Caddyfile
```

The local Caddyfile serves on `:8080` with `init_anubis` + `anubis` in a `handle` block, falling back to `web/` file server.

## Git Identity

Never modify the configured local/global/repository git author. Always set identity via runtime flags only:

```bash
git -c user.name="Claude Mythos" -c user.email=noreply@anthropic.com commit -m "${MESSAGE}"
```

## CI/CD

- **build.yml** - On push/PR: clones the Anubis version in `go.mod`, generates its assets, builds Caddy with a temporary replacement, and runs `go test` and `go vet` with that replacement.
- **dependabot.yml** - Checks the direct Anubis dependency daily and opens update pull requests for new upstream versions.

There are no tests in this repository. `go vet ./...` is the only static check.
