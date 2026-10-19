# Network boundaries for self-hosting

Harbinger's API and Vite client bind to `127.0.0.1` by default. Open
`http://127.0.0.1:5174` after starting with `./manage.sh start`. The client uses
same-origin `/api` URLs, which Vite forwards to the API port with the `/api`
prefix removed. Neither a fresh development session nor a default production
build falls back to the original author's deployment domain.

## Request policy

The API validates the actual `Host` header and any browser `Origin` before
parsing a body or invoking a route handler. Unrecognized hosts and disallowed
origins receive 403 without CORS permission headers. Preflight requests follow
the same checks. Forwarded host or identity headers cannot bypass them.

Loopback hosts `localhost`, `127.0.0.1`, and `[::1]` are allowed. Additional exact
hostnames must be configured in `HARBINGER_ALLOWED_HOSTS`; wildcards, leading-dot
suffix patterns, schemes, userinfo, and ports are rejected. Binding a nonloopback
address does not automatically authorize that hostname. Vite uses the same host
list instead of accepting every hostname.

`CORS_ALLOWED_ORIGIN` is one HTTP(S) origin, without credentials, a path, query,
or fragment. Its default is `http://127.0.0.1:${CLIENT_PORT:-5174}`. Origin values
must match exactly, so `localhost` and `127.0.0.1` are different browser origins.
Use the documented default address or set an explicit origin for another URL.

Some browser resource GET requests omit Origin. The API also rejects no-Origin
requests whose `Sec-Fetch-Site` identifies them as `cross-site` or `same-site`
rather than `same-origin`. Headerless command-line requests remain supported.
These controls reduce cross-origin request triggering and DNS-rebinding exposure;
they do not prove caller identity. Browsers without these headers and nonbrowser
clients can still reach allowed routes when they can reach the service.

## Remote deployment

Remote access still requires a separately configured authenticated reverse proxy
and firewall rules preventing direct access to the API. Do not expose these
processes on the public internet as a complete authentication solution.

For a same-host proxy at `https://intel.example.com`, keep both listeners on
loopback and set these values in the root `.env`:

```dotenv
CORS_ALLOWED_ORIGIN=https://intel.example.com
HARBINGER_ALLOWED_HOSTS=intel.example.com
```

Configure the proxy to authenticate requests, serve the built client, and map
`/api/health` to API `/health`, with the equivalent prefix removal for every API
route. Forward the browser's Origin unchanged and send an allowlisted Host. Strip
client-supplied identity headers before adding any trusted identity information.
The API logs `X-Authentik-*` as reported information and does not validate it.
Vite's development proxy is not a production authentication gateway; use a
production static-file server and authenticated API proxy for a deployed build.

If a proxy runs in another container or host, explicitly configure the required
bind address with `HARBINGER_API_HOST` and restrict network access to that proxy.
`HARBINGER_CLIENT_HOST` controls Vite's development/preview listener. Changing a
bind address does not configure authentication, firewalling, or the allowed Host
list. The development proxy follows `HARBINGER_API_HOST` and `PORT`; a nonloopback
API target must also be allowlisted as an accepted Host.

Separate-origin builds can set `VITE_API_URL=https://api.example.com` in
`apps/client/.env.production.local` before `bun run build`. Allow the API hostname
and set `CORS_ALLOWED_ORIGIN` to the actual dashboard origin. `VITE_*` values are
public build-time configuration and must not contain secrets. Changing a built
client's API URL requires rebuilding it.

## Offline checks and remaining gates

```sh
cd apps/server
bun install --frozen-lockfile --no-env-file
bun test --no-env-file
bunx --no-install tsc --noEmit
cd ../client
bun install --frozen-lockfile --no-env-file
bun test --no-env-file tests/network.test.ts
bun run --no-env-file build
```

The HTTP fixtures run the actual Bun handler in disposable processes with mocked
database, feed, model, and enrichment modules. They test default binding,
configured origins and hosts, denied preflight and simple POSTs, no-Origin browser
metadata, and unchanged handler counters after rejection. The Vite fixtures test
the actual listener, hostname rejection, custom API port, prefix routing for GET
and POST, and preserved Origin enforcement through the proxy. They use synthetic
data and local sockets, with no live provider, feed, or SSH operations.

Authentication, authorization, server-controlled provider destinations, TLS
verification for upstream services, deployment proxy validation, and tenant
isolation remain separate release gates. There is no WebSocket route in the
current Harbinger server, so these tests do not claim WebSocket coverage.

Implementation references: [Bun server binding](https://bun.sh/docs/runtime/http/server#changing-the-port-and-hostname),
[Vite server options](https://vite.dev/config/server-options), and
[browser Origin behavior](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Origin#description).
