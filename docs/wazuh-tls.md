# Wazuh HTTPS trust

Harbinger sends Wazuh credentials and inventory searches to the configured
dashboard console proxy. This connection requires HTTPS and verifies both the
certificate chain and hostname by default. A private network does not establish
the server's identity.

## Configure a trusted connection

Set these values in the repository's `.env` file:

```dotenv
WAZUH_DASHBOARD_URL=https://wazuh.example.test
WAZUH_DASHBOARD_USER=inventory-reader
WAZUH_DASHBOARD_PASSWORD=replace-with-your-local-secret
# Only needed when Wazuh uses a private certificate authority:
WAZUH_CA_FILE=/absolute/path/to/wazuh-ca.pem
```

`inventory-reader` is an example account name, not a built-in or automatically
created user. Provision it or choose a least-privileged account with Dashboard
console-proxy access to query `wazuh-states-vulnerabilities*`, the index pattern
used by the inventory client. Set `WAZUH_DASHBOARD_PASSWORD` to that configured
account's password. If `WAZUH_DASHBOARD_USER` is unset, the runtime retains
`admin` as its existing compatibility fallback.
Obtain the CA certificate through a trusted channel and check its fingerprint
with the administrator. The file contains public CA certificates, never private
keys. It must be a readable PEM bundle containing only CA certificates and
whitespace. An ordinary server certificate is not a CA certificate. The
configured bundle supplies the trust roots for this Wazuh request; do not assume
it is added to the system-wide trust store.

Use an absolute path so launching from `apps/server` or a service does not change
which file is loaded. The server's certificate must cover the URL hostname or IP
address. A CA file does not bypass hostname or certificate validity checks.
Missing, malformed, or unreadable CA files produce a lookup error rather than
falling back to unverified TLS. Restart Harbinger after changing `.env`.

The URL may include a deployment base path, such as
`https://wazuh.example.test/dashboard`. It must not contain embedded credentials,
a query string, or a fragment. HTTP is rejected even when the development
exception below is enabled. Redirects are rejected instead of forwarding the
request: configure the final console-proxy base URL directly. This keeps Basic
credentials and any certificate exception on the configured request.

## Temporary diagnostic exception

For a controlled local diagnostic session only, leave `WAZUH_CA_FILE` unset and
set `WAZUH_INSECURE_TLS=true`. This disables certificate and hostname verification
for Wazuh HTTPS requests and logs a warning on its first use. It permits an
impersonated server to receive Wazuh credentials and provide false inventory
results. Restore verification with a trusted certificate before normal use.

The setting accepts only `true`, `false`, or an unset/empty value; the latter two
keep verification enabled. Combining `true` with `WAZUH_CA_FILE` is rejected to
avoid silently ignoring a trust configuration. This option does not set
`NODE_TLS_REJECT_UNAUTHORIZED` or change feed, model, or other HTTPS requests.
Do not use process-wide TLS overrides as a substitute for this configuration.

## Verify changes without a Wazuh lab

From `apps/server`, with Bun 1.3.14 and OpenSSL on PATH:

```bash
bun install --frozen-lockfile --no-env-file
bun test --no-env-file
bunx --no-install tsc --noEmit
```

The 16 transport cases generate a disposable CA and certificates, start real
loopback HTTPS servers, and call the production inventory client in isolated
subprocesses. They check private-CA success, default rejection of an unknown CA,
hostname mismatch, malformed configuration, HTTPS-only transport, and refusal
to follow redirects. A successful insecure Wazuh request is followed by an
ordinary verified fetch to the same endpoint, which must still fail. Requests
and redirects remain on disposable local listeners; no Wazuh, feed, or model
service is contacted. Temporary keys are removed after the suite.

The `Wazuh transport` workflow runs the complete server suite and TypeScript
checks on Ubuntu and macOS. These fixtures verify transport behavior, not a live
Wazuh proxy version, user permissions, inventory completeness, authentication of
Harbinger callers, or production deployment. Retain those separate release gates.
