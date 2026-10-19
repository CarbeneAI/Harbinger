# Client validation

Run these commands from the repository root using Bun 1.3.14 and Node.js 22,
the versions selected by the client type safety workflow:

```bash
cd apps/client
bun install --frozen-lockfile
bun run typecheck
bun run build
```

`typecheck` runs `vue-tsc --noEmit` over client source TypeScript and Vue
single-file components, including their templates. It extends the installed
`@vue/tsconfig` browser configuration, retains strict checking, and includes
Vite's client environment types. The dependency versions come from the existing
client lockfile. The command does not emit application files.

The Vite build produces the browser bundle but does not perform typechecking.
Both commands must pass. CI runs them as separate steps so a type error cannot
be mistaken for a successful build. See the
[Vue TypeScript guide](https://vuejs.org/guide/typescript/overview.html).

## Feed poll time

The `/feeds` response and `Feed` type expose `last_poll`, a timestamp in
milliseconds since the Unix epoch. The feed health popover uses this field and
formats it in the browser's local time. It omits the line when the value is
missing or null, and accepts zero as a valid timestamp.

This is the last poll status update, including an error, rather than proof of
the last successful refresh. The existing server status and timestamp semantics
are unchanged. The status and error message remain visible alongside the time.

The previous template referenced `last_poll_at`, which is absent from `Feed`
and the database response. With the client configuration in place, `vue-tsc`
reports both mistaken references and exits unsuccessfully. Keeping template
checking enabled prevents that field-name regression from passing CI again.

## Scope

The configuration checks `src/**/*.ts` and `src/**/*.vue`. Server code, Vite's
Node.js configuration, and browser test fixtures outside `src` are not included
in this browser-source typecheck. Static checking does not validate remote JSON
at runtime or establish live feed, database, Wazuh, or model connectivity.
