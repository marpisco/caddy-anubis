# caddy-anubis

A Caddy module that integrates [Anubis](https://github.com/TecharoHQ/anubis) proof-of-work challenges to protect upstream resources from scraper bots and AI crawlers.

Source: [marpisco/caddy-anubis](https://github.com/marpisco/caddy-anubis)

## Installation

The Anubis Go module does not include its generated browser assets. Build Caddy from a checkout with a matching Anubis checkout whose assets have been generated.

This requires Go 1.26.3 or newer, Node.js 24 or newer, npm, gzip, zstd, brotli, and xcaddy.

```bash
git clone https://github.com/marpisco/caddy-anubis.git
cd caddy-anubis

go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

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

## Usage

Add `anubis` where protection is needed. It works at the top level and inside `route`/`handle` blocks:

```caddy
:80 {
    handle {
        anubis
        reverse_proxy localhost:8080
    }
}
```

The module passes Caddy's resolved client IP to Anubis. When Caddy is behind a proxy, configure Caddy's trusted proxy settings so it resolves the original client IP correctly.

### Options

```caddy
anubis {
    # Redirect to a fixed URL instead of proxying to the next handler
    target https://example.com

    # Path to a custom Anubis policy file
    policy_file /etc/anubis/policy.yaml
}
```

## Credits

- [Anubis](https://github.com/TecharoHQ/anubis) - the proof-of-work challenge engine.
