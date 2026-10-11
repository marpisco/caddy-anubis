# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with codebase.

## Project Overview

This is a **Caddy HTTP server module** that integrates [Anubis](https://github.com/TecharoHQ/anubis) proof-of-work challenges to protect upstream resources from scraper bots and AI crawlers. It provides two Caddyfile directives:

- **`init_anubis`** - Site-level directive: the Anubis server of a site. Serves the assets and challenge API at `/.within.website/` and holds the site's options. Place once per site block, outside `handle`.
- **`anubis`** - Handler-level middleware that enforces the challenge. Can be used at the top level or inside `handle`/`route` blocks to protect specific paths.

## Key Dependencies

- **Caddy v2** (`github.com/caddyserver/caddy/v2`) - The host server framework.
- **Anubis** (`github.com/TecharoHQ/anubis`) - The upstream proof-of-work challenge engine. Its Go module excludes generated browser assets, so builds clone the pinned tag and generate assets locally.

## Architecture

The entire plugin is a single Go file: `caddy_anubis.go`. There is one Anubis server per site and no process-wide state.

- **`anubisOptions`** - Options shared by both directives (`policy_file`, `serve_robots_txt`, `cookie_domain`, `opengraph_target`, `ed25519_private_key_hex_file`), embedded in both middleware structs. One Caddyfile parser (`unmarshalOption`) and one constructor (`newServer`). A new shared option goes here.
- **`initAnubisMiddleware`** - Registered via `RegisterDirective` with a route that matches every request of the site. Serves `/.within.website/*` with its server; for any other path it publishes its server in the request vars (`siteServerVarKey`) and calls next.
- **`AnubisMiddleware`** - Uses the site's server from the request vars when `init_anubis` is present, otherwise its own server (standalone). With options that server is built in `Provision`, so a broken policy fails the load; without options it is built on the first request that needs it, because every policy load leaves an Anubis goroutine behind. Has the per-handler option `target <url>`. Setting a shared option on it in a site with `init_anubis` answers 500.

Anubis only takes a plain `http.Handler` as its next handler, so the Caddy next handler travels in the request context (`downstream`), which also carries its error back to Caddy.

### Caddyfile Example

```caddy
:8080 {
    init_anubis          # Site: Anubis server, assets and challenge API

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

## Commit style

Use Conventional Commits with this title format:

```text
type(scope): short message
```

Examples:

```text
feat(reservations): add room filter
fix(login): handle expired session
refactor(admin): simplify approval flow
```

Use a longer body after the title. Explain what changed, why it changed, and important behavior or testing.

## CI/CD

- **build.yml** - On push/PR: clones the Anubis version in `go.mod`, generates its assets, builds Caddy with a temporary replacement, and runs `go test` and `go vet` with that replacement.
- **dependabot.yml** - Checks the direct Anubis and Caddy dependencies daily and opens update pull requests for new upstream versions.

Tests (`*_test.go`) start a real Caddy through `caddytest` on ports 2999 and 9080 and need the Anubis checkout with generated assets (see build.yml for the `-modfile` replacement). `go vet ./...` is the static check.
