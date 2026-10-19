# Feed request deadlines

Harbinger applies its existing 30-second deadline to each CISA KEV, URLhaus and ThreatFox request, including native response-body consumption. Previously the helper cleared its timer as soon as headers arrived. A server could return HTTP 200 and part of its JSON, then leave that feed and the cycle waiting indefinitely.

The private fetch helper now attaches a native `AbortSignal.timeout(30_000)` signal to the request. Successful responses keep that signal during the caller's JSON read. For non-OK HTTP responses, an explicit controller also aborts the request and awaits cancellation of its unused body, then returns the same `Response`. The pollers retain their existing HTTP-status diagnostics, request methods, authentication headers and JSON processing.

This uses the native signal composition and fetch behavior verified on Bun 1.3.14. Bun documents [fetch cancellation](https://bun.sh/docs/runtime/networking/fetch); its [idle timeout](https://bun.sh/reference/globals/BunFetchRequestInit/timeout) is a separate policy. The native deadline is not explicitly canceled after a successful request. The fixtures prove that a completed request with a 30-second signal does not keep its child process alive. They do not claim immediate reclamation of the runtime's internal timer or listeners.

## Offline evidence

Run from the repository root with Bun 1.3.14:

```sh
cd apps/server
bun install --frozen-lockfile --no-env-file
bun --no-env-file test
bunx --no-install tsc --noEmit
```

The standalone suite contains 38 tests, including ten subprocess scenarios in `src/feed-request-deadlines.test.ts`. They call production `pollAllFeeds()` with temporary real SQLite databases and real HTTP streams bound to `127.0.0.1` on disposable ports. No external feeds or credentials are used. Only the deadline clock is shortened in failure scenarios; the configured production policy remains 30 seconds.

The cases cover stalled bodies for all three feeds, delayed headers, HTTP 503 with stalled unused bodies for all feeds, malformed JSON, a reset after headers, and a successful request with the actual 30-second signal. Assertions check actual server-stream cancellation, preserved HTTP diagnostics, no IOC writes or success status for the failed feed, preserved historical count, successful peer feeds, and recovery on a subsequent valid cycle. A fixture rescue releases old behavior so baseline failures clean up rather than leave services running.

The fixture also accepts an explicit `joined` argument for a composition containing feed-cycle coordination. That additional integration check verifies a held body still owns the shared cycle and a concurrent caller joins it. This standalone change does not introduce scheduler coordination itself.

## Limits and followups

- This is an asynchronous request and body-wait deadline. JavaScript timers cannot interrupt synchronous JSON parsing, response validation, mapping, SQLite work or full-text index rebuilding. It is not a whole-cycle execution budget or response-size limit.
- Abort settlement depends on Bun's native fetch implementation. Tests cover the pinned runtime on the supported CI platforms; they do not establish every proxy, remote server or future Bun version's behavior.
- Each feed failure continues to be recorded through the existing orchestration. This change adds no retries, backoff, new diagnostics, transactional behavior, feed-response validation, FTS-health redesign or deployment assurance. Other contributions cover some of those concerns independently.
- Future work can measure real catalog size and local processing time before proposing size or processing budgets. Keep any retry policy and cycle ownership explicit rather than detaching work with `Promise.race`.

Contribution: Ryan Wentzel, https://ryanwentzel.me.
