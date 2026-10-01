# ADR-0005: MCP discovery methods require authentication

Status: Superseded — see note below. The decision recorded here (Option 1)
was never merged; the maintainer shipped Option 2 directly, in commits
`91d2033` ("fix(ai-team): explicit CORS allowlist and documented public
discovery (#3556)") and `2578961` (version bump to 0.1.6), both on `main`
as of 2026-09-30. Discovery (`initialize`, `ping`, `tools/list`,
`prompts/list`, `resources/list`) stays intentionally anonymous; the actual
fix replaces the wildcard CORS header with an explicit origin allowlist
(`chatgpt.com`, `chat.openai.com`, `claude.ai`, or `ALLOWED_ORIGINS`) so
only those origins — not arbitrary web pages — can read the discovery
responses cross-origin, and documents which methods are public and why in
the plugin README. `tools/call` and non-UI `resources/read` still require
OAuth, unchanged.

This record is kept for the design-option history (both options and their
tradeoffs are still accurate reading), but the "Decision" section below
does **not** reflect what shipped. Rationale for the option that did ship
lives in the two commits above, not in this document.

## Context

An external researcher testing the live `team.ruv.io/mcp` deployment (plugin
v0.1.4) with no `Authorization` header found that `GET /mcp`, `initialize`,
`tools/list`, and `prompts/list` all return `200` with full service metadata,
capabilities, and all twelve tool definitions (names, descriptions, JSON
Schemas, annotations) — including the definition of `team_create`, the
service's most consequential write tool. `resources/read` and `tools/call`
correctly return `401 {"error":"invalid_token"}`. The four unauthenticated
`200` responses also carry `access-control-allow-origin: *`, so any web page
can read them cross-origin. Ref: ruvnet/ruflo#3556.

Two defensible fixes were identified: (1) require a token for every MCP
method except the `401` challenge response itself, matching `resources/read`
and `tools/call` today; or (2) keep discovery intentionally public and narrow
the wildcard CORS header on the listing responses so only direct/server-side
callers, not arbitrary browser pages, can read them.

## Decision

Require a valid token for every `plugin/ruflo-ai-team` MCP method — `GET
/mcp`, `initialize`, `tools/list`, `prompts/list`, `resources/read`, and
`tools/call` alike — except the `401` challenge response itself. This matches
the enforcement `resources/read` and `tools/call` already have and is
consistent with this service's existing posture: ADR-0001 already treats the
public MCP surface as data behind a verified tenant boundary, not an open
directory, and the plugin has no precedent anywhere else of exposing anything
authless beyond the documented `401`-unless-authenticated guarantee.
Uniform enforcement also matches the MCP authorization spec's expectation
that an unauthenticated caller gets a consistent `401` + `WWW-Authenticate`
challenge across methods, which is what lets a client discover the
authorization server without having to special-case which methods need a
token.

Option 2 (public discovery + narrowed CORS) was considered and rejected.
Even with CORS scoped down, any direct or server-side caller would still see
the full write surface — `team_create` plus the other eleven tool
definitions — for free, with no token and no rate limiting tied to identity.
The disclosure was rated modest with twelve tools; that is not a standard
this service should commit to as its tool surface grows. A single consistent
rule (token required everywhere but the challenge) is also simpler to reason
about and audit than a rule that is fail-closed for four methods and
intentionally open for four others.

This ADR does not itself implement the fix. The `team.ruv.io` deployment is a
gateway/service configuration that may live outside this repository; the
`plugin/ruflo-ai-team` MCP method list above is authoritative and fixed here
so that whatever change lands, in this repo or the deployment config, has a
clear target to conform to: unauthenticated requests to any method other than
the `401` challenge are a compliance violation.
