# Proposed contributor roadmap

This is a contributor proposal for maintainer discussion, not an adopted release plan. It complements the [product roadmap](README.md#roadmap) by prioritizing trustworthy enrichment and reproducible checks. The maintainer decides scope, ordering, and scheduling.

## Baseline in this contribution

- Preserve the distinction between a failed Wazuh lookup and confirmed CVE absence in analysis context.
- Cover failed, absent, present, and unconfigured exposure through the production context builder with isolated sources.
- Preserve available, stale, and unavailable KEV states through the real signal producer, formatter, health response, and analyst context. Validate consumed catalog fields before cache promotion; retain old timestamps after failed refreshes.
- Validate completed Wazuh searches, exact CVE counts, and required aggregates through offline HTTP fixtures; partial or malformed responses remain unknown.
- Document current provider routing, CVE prefetch, and external data flows.
- Run server tests/typechecking and the client build in CI with frozen dependency installs.

Current offline commands and limitations are in the [contributor guide](README.md#offline-checks-for-contributors-and-coding-agents). These checks do not exercise live feeds, Wazuh, SSH, or model responses.

## 1. Extend enrichment failure coverage

Problem: unavailable or stale external evidence must not become a confident absence claim.

Proposed approach: extend the Wazuh response fixtures to additional sources and cache expiry, including EPSS validation and interactions between partially available enrichment sources. KEV cache-state coverage is included in this contribution; full-body fetch deadlines, persistent source health, and cross-process cache coordination remain separate follow-ups.

Acceptance criteria:

- Each source distinguishes confirmed absence from unavailable or stale evidence.
- Production code paths are exercised with a controlled clock and mock transports.
- Tests reject unexpected network access and do not depend on live feed contents.
- User-facing context identifies which evidence is unavailable without fabricating a finding.

## 2. Make provider capabilities explicit

Problem: CVE prefetch currently belongs to the Claude CLI path; callers can otherwise assume the same behavior across providers.

Proposed approach: agree on a documented capability matrix before deciding whether enrichment should be shared across providers.

Acceptance criteria:

- Claude CLI, Anthropic, and Ollama inputs, tools, and data destinations are described from current code.
- Mocked provider tests verify any newly shared enrichment and its failure behavior.
- Network-visible data and local-only data are explicitly identified in configuration documentation.
- Existing provider behavior remains covered while any parity change is introduced separately.

## 3. Keep configuration and documentation synchronized

Problem: removed integrations and changed environment variables can leave misleading setup instructions behind.

Proposed approach: validate local documentation links and maintain a small checked configuration reference for supported variables.

Acceptance criteria:

- Referenced files and sample variables resolve to supported code or are clearly labeled optional examples.
- Documentation checks have a documented local command and run without secrets.
- Human and coding-agent instructions use the same supported installation and validation commands.
- Live-integration smoke tests remain opt-in, with explicit prerequisites and sanitized results tied to a commit.

## Proposed release gates

Self-hosted readiness still needs verified connection trust, explicit API access boundaries behind an authenticated proxy, safe rendering of model output, and a disposable install/restart/backup/restore check. The current fixture suite and this contribution do not establish those gates.

Hosted readiness follows the self-hosted gates and also requires tenant isolation, server-controlled provider destinations and credentials, per-user authorization and audit records, and bounded job, rate, and spending limits. These are proposed acceptance areas for maintainer discussion, not claims that hosting is currently safe or supported.

## Contribution standard

Keep each change independently reviewable. Explain the user impact, cause, chosen solution, regression evidence, and remaining limitations. Update related README text, environment examples, and non-obvious inline comments in the same change.

Proposed by Ryan Wentzel, [ryanwentzel.me](https://ryanwentzel.me).
