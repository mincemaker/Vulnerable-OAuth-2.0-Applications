# insecureapplication-go

GUTS Stack (Go) port of [`insecureapplication`](../insecureapplication)'s `gallery` and `photoprint`. Same deliberately vulnerable OAuth 2.0 behavior, same PoCs (see [`doc/OAuth2_PoC_Verification_Report.md`](../doc/OAuth2_PoC_Verification_Report.md)), different implementation:

- [`gallery-idp`](./gallery-idp) — the authorization server + resource server (`gallery`), Go/SQLite.
- [`photoprint-client`](./photoprint-client) — the OAuth 2.0 client (`photoprint`), Go.

`attacker` hasn't been ported yet and still runs from [`../insecureapplication/attacker`](../insecureapplication/attacker) (Node.js).

For Docker/Podman Compose, see [`../insecureapplication/README.md`](../insecureapplication/README.md) — `compose.yml` already builds these two directories.

## Running on host (Go >= 1.26.5)

Each service is a self-contained binary; run them from two terminals.

```bash
# 1. Gallery (IdP / Resource Server) -- self-seeds its SQLite DB on first run
cd gallery-idp && make dev

# 2. PhotoPrint (Client)
cd photoprint-client && make dev
```

Then open [http://photoprint.127.0.0.1.nip.io:3000](http://photoprint.127.0.0.1.nip.io:3000) (credentials: `koen` / `password`).

`make build` compiles a standalone binary (`./gallery-idp`, `./photoprint-client`) instead of running via `go run`; run it the same way you'd run `make dev`.

### Configuration

Both services read config from environment variables (`CLIENT_ID`, `CLIENT_SECRET`, `SESSION_SECRET`, `GALLERY_URL`, `GALLERY_BROWSER_URL`); see each `Makefile` for the exact list and defaults. The defaults already work for the `*.127.0.0.1.nip.io` setup above, so no configuration is required to get started.

If you need to override something (e.g. `gallery-idp` isn't at `localhost:3005`), the repo-root [`mise.toml.sample`](../mise.toml.sample) is the single source of dev config for both services — copy it to `mise.toml` and mise's shell activation applies it in any subdirectory. Without mise, prefix the variable inline instead:

```bash
GALLERY_URL=http://localhost:3005 make dev
```
