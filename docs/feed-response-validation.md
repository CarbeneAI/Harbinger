# Feed import integrity

HTTP 200 does not establish that a feed query succeeded. Harbinger validates each
complete response against the consumed field contract before the first IOC
upsert from that feed. A rejected response records an error for that feed and
writes none of its IOCs. The other feeds still settle independently and retain
their own status/counts; full-text index rebuilding remains after settlement.

This is a bounded response gate, not complete provider JSON-schema validation.
Extra fields are allowed. Existing IOC mapping, severity, tag construction,
source references, timestamps, endpoints and authentication are unchanged.
The validators do not normalize IOC values. Cycle coordination is described below.

## Accepted response contracts

### CISA KEV

The envelope requires a nonempty `catalogVersion`, a parseable finite
`dateReleased`, a vulnerabilities array, and a nonnegative safe-integer `count`
matching that array's length. Each row must be an object with a schema-shaped
`cveID`, string vendor/product/name/description fields, and a real calendar
`dateAdded` in `YYYY-MM-DD` form. Optional `knownRansomwareCampaignUse` must be a
string when present; labels are not restricted to an enum.

This follows the consumed fields of the
[pinned official CISA schema](https://github.com/cisagov/kev-data/blob/6a392940c663b52271fa4e6aa7b39995b18c9a71/known_exploited_vulnerabilities_schema.json).
Unused fields such as `requiredAction`, `dueDate` and `cwes` are not validated.
The release date is checked for finite parsing, not the schema's full date-time
format. This is not a claim that every catalog field satisfies that schema.

### URLhaus

The [recent-URL documentation](https://urlhaus-api.abuse.ch/#recent) describes
`ok` and `no_results`. `ok` requires an actual `urls` array, including an empty
array. For `no_results`, this application accepts absent/null/empty `urls` and
rejects contradictory or wrongly typed rows. That shape policy is our validation
choice; the provider documentation does not specify every empty variant.

Rows require a nonempty URL string. Optional `url_status` and `threat` are
absent/null or strings; optional dates must be nonempty parseable strings.
Absent/null dates keep the existing current-time fallback. Unused provider
`tags` are not validated or newly imported. URL syntax and scheme restrictions
are not added: the existing mapper retains the URL IOC and only extracts a
host when `new URL` can parse it.

### ThreatFox

The [recent-IOC documentation](https://threatfox.abuse.ch/api/#recent) shows an
`ok` envelope with a `data` array. Harbinger retains its `ok`-only rule; other or
missing statuses fail, including `no_result`. Rows require nonempty string IOC
type/value fields. Unsupported types still skip their unconsumed metadata.

For supported types, optional confidence is absent/null or a finite number in
0..100; optional malware is absent/null/string; optional tags are absent/null or
an array of strings. Present dates must be nonempty parseable strings.
Absent/null confidence still maps to zero; absent/null first-seen dates use the
current time, and absent/null last-seen dates use first-seen. Existing supported
type mapping, including the current `ip:port` splitting behavior, is unchanged.

## Diagnostics and limits

Response-validation and JSON-decoding failures use fixed per-feed messages.
They do not echo response status values, rejected records, decoder exceptions,
or credentials. This does not sanitize every transport or database exception;
the existing orchestration still surfaces other error messages.

## Atomic persistence after validation

Each poller fetches, validates and maps its complete response before opening a
synchronous SQLite transaction. `commitFeedImport` commits every IOC upsert and
the successful feed status/count together. A failed write or status update rolls
back the whole batch, including changes to existing rows and feed ownership.
The caller then attempts to record the feed error while preserving the last
successful count. A database failure that also prevents this error-status write
cannot guarantee persisted diagnostics. Other feeds still commit independently. A later successful poll clears
the error; a valid empty batch reports zero without deleting historical rows.

IOC writes and status updates use one prepared statement each so SQLite errors
propagate into the transaction. Regression fixtures inject real SQLite trigger
failures; they do not mock the persistence layer. Keep network requests and all
other asynchronous work outside the transaction.

A successful count remains the mapper's IOC upsert-operation count, which may
include URL plus domain operations or repeated values, not unique new rows.
The full-text index is rebuilt after all feeds settle, outside these per-feed
transactions. An index rebuild failure is still logged separately and does not
roll back committed IOCs. This does not provide pagination, crash-recovery
testing or feed completeness.

## One active feed cycle per process

Scheduled, manual and direct `pollAllFeeds` callers share one active cycle.
Concurrent calls return the same promise and join its settlement. They do not
start another cycle, queue a later cycle or replay a skipped interval tick.
A later scheduled or manual request can start a new cycle after settlement.
The three feeds within a cycle still run concurrently and settle independently.

The coordinator owns the slot before invoking fetch, including synchronous
fetch reentry. It holds ownership through response-body reading, validation,
mapping, each synchronous import, `Promise.allSettled`, the FTS rebuild,
statistics and final logging. A `finally` clears ownership after the actual
cycle settles, including rejection before fetch or during final statistics.
Individual feed failures continue to record their existing status when possible;
they do not reject the whole cycle merely because a feed failed. Per-feed
IOC/status transactions and successful peers are preserved.

`startFeedScheduler` installs one interval per process, at the unchanged
`POLL_INTERVAL_MS` cadence (one hour by default). It registers the timer before
starting the immediate stale/unpopulated-feed cycle, so synchronous startup
reentry cannot install another timer. Repeated starts are no-ops, including
after a cycle finishes. Fresh feeds still wait for the next scheduled tick.
If synchronous initialization fails before timer registration, a later start
can retry initialization. This is not a scheduler stop/reconfiguration API.

`POST /feeds/poll` keeps its immediate HTTP 200 and `triggered: true` response,
with message `Poll started or already running`. It acknowledges requesting or
joining work, not completed import success or a queued second cycle. The existing
client ignores the response body and still performs its later refresh. Manual
cycle rejections are logged, as scheduler rejections already were; clients must
inspect feed status separately. No cycle ID, progress API or UI polling redesign
is added.

This guard is process-local. Multiple Harbinger processes can still run separate
cycles against the same database. There is no timeout or cancellation added:
the existing fetch timer ends at response headers, so a never-settling body can
hold the active cycle indefinitely. Releasing a slot with `Promise.race` while
underlying work continues would break this contract and is not used. Full-body
deadlines require their own runtime/transport fixtures. FTS failure visibility,
successful-versus-attempt timestamps, recent-feed windows, retry/backoff,
provenance and durable recovery remain separate proposals.

## Proposed followups

Before claiming durable, lossless or complete ingestion, review database
crash recovery, recent-feed window limits, pagination, retries,
provider schema/version changes, IOC semantic validity, and timestamp/timezone
policy separately. URLhaus documents a bounded recent window, and ThreatFox's
request still asks for seven days; this change does not fetch older data or
prove feed completeness. These are proposals, not adopted commitments.

## Offline checks and maintenance

With Bun 1.3.14, from `apps/server`:

```bash
bun install --frozen-lockfile --no-env-file
bun --no-env-file test
bunx --no-install tsc --noEmit
```

The standalone upstream-based branch has 145 server tests: 28 existing cases,
90 response fixtures, 8 real-database transaction scenarios and 19 cycle-coordination
scenarios. Focus response cases with
`bun --no-env-file test src/feed-validation.test.ts`. The new workflow runs the
full locked suite and TypeScript, including fixture files, on Ubuntu and macOS.
The corrected server lock matches the other reviewed Harbinger contributions;
no dependency is added to the manifest.

Response fixtures call production `pollAllFeeds` in isolated Bun children, replacing the
database and fetch with in-process stubs. They exercise valid/empty data,
HTTP-200 error envelopes, bad identities/dates/tags, valid-first/bad-later rows,
nullable and absent fallbacks, unsupported types, original mappings, independent
statuses/counts, and fixed validation diagnostics. Every rejected feed makes zero
IOC writes while its peers succeed. No live feed, credentials, model, provider or scheduler is used. Transaction
fixtures use an owned temporary SQLite database, cleaned after each scenario.
They cover insert and overwrite rollback, derived-domain failures, successful
status-update failures, independent searchable feeds, retry, empty results and
duplicate operation counts. Focus them with
`bun --no-env-file test src/feed-atomicity.test.ts`.

Cycle fixtures invoke actual `pollAllFeeds` and `startFeedScheduler` in isolated
Bun children with owned real SQLite databases, synthetic fetch responses and
captured interval callbacks. Real SQLite triggers count insert/update/status
effects and inject failures. One fixture instruments statement preparation on
the real connection to test synchronous import reentry; persistence still runs
in SQLite. The cases prove one active fetch set, no extra imports, shared promise
identity, ownership through body/FTS/final logging, repeated fresh/stale starts,
first-fetch scheduler reentry, initialization retry, independent feed failures
and later recovery after whole-cycle rejection. The HTTP case runs the real
server entrypoint on an ephemeral loopback port and joins manual and scheduled
requests while a body is held. It stops the server and cleans its temporary data.
Focus these with `bun --no-env-file test src/feed-single-flight.test.ts`.
All 19 fail against the prior implementation and pass with coordination.
No live feed, model, credentials or production service is involved.

Do not move validation into the upsert loop: every row must be checked before the
first IOC write. Preserve both complete-response validation and atomic
persistence when changing the contract.

Cycle-coordination followup contributed by Ryan Wentzel, https://ryanwentzel.me.
