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

There are two directives:

- `init_anubis` is the Anubis server of a site. Place it once in the site block, outside any `handle`. It serves the challenge assets and API under `/.within.website/` and takes the site's options.
- `anubis` is where the challenge is enforced. Place it in front of what should be protected, at the top level or inside `route`/`handle` blocks.

```caddy
example.com {
    init_anubis {
        policy_file /etc/caddy/anubis/policy.yaml
    }

    # Called by programs: no challenge
    handle /api/* {
        reverse_proxy localhost:8080
    }

    # Everything else is protected
    handle {
        anubis
        reverse_proxy localhost:8080
    }
}
```

Every site has its own Anubis server, with its own policy, signing key and challenge store. Sites in the same Caddy do not affect each other, and a site without these directives is left alone.

A site that protects everything can use `anubis` alone, with the options on it:

```caddy
example.com {
    anubis {
        policy_file /etc/caddy/anubis/policy.yaml
    }
    reverse_proxy localhost:8080
}
```

Without `init_anubis`, the `anubis` handler must also receive the requests to `/.within.website/`, so do not scope it to a path.

### Options

`init_anubis` and a standalone `anubis` take the same options:

```caddy
init_anubis {
    # Path to an Anubis policy file. Default: the policy built into Anubis.
    policy_file /etc/caddy/anubis/policy.yaml

    # Domain attribute of the Anubis cookie. Default: none (host-only cookie).
    cookie_domain example.com

    # Where Anubis fetches the real pages to read their Open Graph tags.
    # Required when the policy enables openGraph without overrides.
    opengraph_target http://localhost:8080

    # Let Anubis answer /robots.txt with its built-in file.
    # Default: off, the site's own robots.txt is served.
    serve_robots_txt
}
```

`anubis` has one option of its own, which works in both layouts:

```caddy
anubis {
    # Redirect allowed visitors to a fixed URL instead of calling the next handler
    target https://example.com
}
```

In a site with `init_anubis`, `target` is the only option an `anubis` handler may set. Any other option on it makes its requests answer 500, so put them on `init_anubis`.

An unknown option, a missing argument, a missing or invalid policy file fails `caddy validate` and `caddy reload`; the running configuration keeps serving.

### Policy file

Everything else is configured in the [Anubis policy file](https://anubis.techaro.lol/docs/admin/policies): the rules, the challenge difficulty (`thresholds` and the `challenge` of a rule), the store backend (`store`) and Open Graph passthrough (`openGraph`).

A client that matches no rule is allowed by Anubis' default thresholds. A policy that only challenges browser-like user agents lets a client such as `curl` through; add a catch-all rule if that is not wanted.

### Client address

The module passes Caddy's resolved client IP to Anubis and overwrites any `X-Real-IP` header sent by the client. When Caddy is behind a proxy, configure Caddy's trusted proxies so it resolves the original client address:

```caddy
{
    servers {
        trusted_proxies static 173.245.48.0/20 103.21.244.0/22
        trusted_proxies_strict
        client_ip_headers CF-Connecting-IP
    }
}
```

Without trusted proxies, client-address headers are ignored and the address of the direct peer is used.

### Limitations

- The signing key and the default in-memory store are created when the configuration is loaded. After a `caddy reload` or a restart, visitors solve the challenge again.
- With Open Graph passthrough, Anubis requests the page from `opengraph_target` with the visitor's `Host` header while it builds the challenge page.

## Development

Tests start a real Caddy on ports 2999 and 9080 and need the Anubis checkout with generated assets, as in the installation steps:

```bash
cp go.mod /tmp/go.mod && cp go.sum /tmp/go.sum
go mod edit -modfile=/tmp/go.mod -replace=github.com/TecharoHQ/anubis="$ANUBIS_DIR"
go test -modfile=/tmp/go.mod ./...
go vet -modfile=/tmp/go.mod ./...
```

## Credits

- [Anubis](https://github.com/TecharoHQ/anubis) - the proof-of-work challenge engine.
