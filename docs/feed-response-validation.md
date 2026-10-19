# Feed response validation

HTTP 200 does not establish that a feed query succeeded. Harbinger validates each
complete response against the consumed field contract before the first IOC
upsert from that feed. A rejected response records an error for that feed and
writes none of its IOCs. The other feeds still settle independently and retain
their own status/counts; full-text index rebuilding remains after settlement.

This is a bounded response gate, not complete provider JSON-schema validation.
Extra fields are allowed. Existing IOC mapping, severity, tag construction,
source references, timestamps, endpoints, authentication, scheduler and retry
behavior are unchanged. The validators do not normalize IOC values.

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

Prevalidation prevents writes caused by a partly malformed response. Database
failures after a valid response can still leave partial writes: there is no new
transaction, rollback, schema migration or atomicity guarantee. A feed error does
not erase older database rows or turn another feed's successful count into zero.
A successful count remains the mapper's IOC upsert-operation count, which may
include URL plus domain operations, not unique new rows.

## Proposed followups

Before claiming durable, lossless or complete ingestion, review database
transactions/failure recovery, recent-feed window limits, pagination, retries,
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

The standalone upstream-based branch has 118 server tests: 28 existing cases
and 90 response fixtures. Focus the new cases with
`bun --no-env-file test src/feed-validation.test.ts`. The new workflow runs the
full locked suite and TypeScript, including fixture files, on Ubuntu and macOS.
The corrected server lock matches the other reviewed Harbinger contributions;
no dependency is added to the manifest.

Fixtures call production `pollAllFeeds` in isolated Bun children, replacing the
database and fetch with in-process stubs. They exercise valid/empty data,
HTTP-200 error envelopes, bad identities/dates/tags, valid-first/bad-later rows,
nullable and absent fallbacks, unsupported types, original mappings, independent
statuses/counts, and fixed validation diagnostics. Every rejected feed makes zero
IOC writes while its peers succeed. No live feed, credentials, database, model,
provider or scheduler is used. Do not move validation into the upsert loop: every
row must be checked before the first IOC write. Preserve the distinction between
response rejection and database atomicity when changing this contract.
