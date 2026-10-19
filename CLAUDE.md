# Harbinger development checks

## Untrusted Markdown output

Keep assistant HTML insertion behind `apps/client/src/lib/markdown.ts`.
The helper must sanitize after Markdown parsing; do not return raw parsed HTML
or post-process it into additional HTML. Preserve the strict tag, attribute,
and HTTP(S)-only link policy. Model-provided images must not fetch resources.
The ChatPanel and printable brief share this helper. Markdown downloads retain
untrusted source and need safe rendering elsewhere.

From `apps/client`, run `bun install --frozen-lockfile`,
`bunx playwright install chromium`, `bun --no-env-file run test:markdown`, and `bun run build`.
The browser test CLI uses Node.js 22 alongside Bun 1.3.14. Tests mount the real
component with synthetic data on an isolated loopback fixture and block requests
after loading. Do not use live services or credentials to run these checks.
See `docs/markdown-safety.md` for policy, maintenance, and validation limits.
