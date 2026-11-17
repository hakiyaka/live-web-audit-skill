# Reconnaissance

### Phase 1: Map the live site and plan coverage

The parent writes `run-metadata.json` and `scope.json`, applies the budget gate in `SKILL.md`, then creates the ledger before any hunting. Reconnaissance is passive: normal page fetches, asset fetches, `robots.txt`, `sitemap.xml`, `/.well-known/`, TLS, and DNS. No crafted parameter, no state change, no authentication attempt.

Launch several `research` agents in parallel. Each receives the scope file, the output directory, and its own `agents/<agent-id>/` root. Every observation goes through the harness so that a capture backs it:

```bash
node <skill-dir>/probes/harness.mjs fingerprint --url <origin>/ --scope <output-dir>/scope.json --out <output-dir>/agents/<agent-id>/artifacts/root-fingerprint.json
```

**Agent 1a: origin, hosting, and transport**

```text
Map the origin's transport and hosting from the outside. Use only the harness
(headers, tls, dns, redirect, cookies) and passive fetches of pages the site serves.
Return:
1. Origin(s), redirect chain from http, final scheme, HSTS presence and max-age.
2. TLS: protocol, cipher, certificate issuer, validity, SAN coverage, chain problems.
3. Hosting and edge: server headers, CDN hints, WAF or challenge pages, alternate origins.
4. DNS: A/AAAA/CNAME/NS/MX/TXT/CAA; note anything security-relevant (SPF/DMARC/CAA gaps).
5. Cookie inventory with names and flags (values are redacted).
6. Response-header posture for HTML, API, and static assets separately.
Every claim cites one capture path under agents/<agent-id>/artifacts/.
```

**Agent 1b: application shape and entry surfaces**

```text
Read the site the way a visitor does. Fetch the home page, the main navigation
targets, and any linked API or form. Return:
1. Product type, user roles visible on the site, and the ordinary trust-sensitive
actions (login, checkout, profile edit, upload, invite, export, admin).
2. URLs and route families (with the method the site itself uses), grouped by surface.
3. Authentication surfaces: login, register, password reset, MFA, SSO callbacks.
4. Third-party hosts the pages call, and which of them are in scope.
5. Frameworks and versions visible from markup and response headers, with the marker.
6. Forms: action, method, hidden fields (names only), CSRF token names, enctype.
Record every distinct URL you rely on in your artifact notes and keep the captures.
```

**Agent 1c: identities, sessions, and trust boundaries**

```text
Using only the operator-supplied test identities (if any), map identity:
1. What changes when the test identity logs in: cookie names, headers, redirects,
   visible routes, and any role marker.
2. Where the site decides identity: cookie, bearer token, header, path prefix, subdomain.
3. Which actions are available anonymously, which need identity, which need a role.
4. Session lifecycle: value rotation at login, logout effect, remember-me, expiry hints.
5. Which boundaries you can probe with the identities available, and which are blocked.
6. If no second identity exists, state exactly which access-control questions stay open.
Never register an account. Never attempt credential guessing. Capture each step.
```

**Agent 1d: client assets and data exposure**

```text
Fetch and read the client assets of the public surfaces. Return:
1. Script bundles, their sizes, and any source maps (URL + map name only).
2. Endpoint strings, absolute internal hosts, feature flags, tenant or environment ids,
   and key-shaped strings (classify public vs secret by name and placement).
3. Routes that exist in the client but are not linked in the markup.
4. Markup sinks: inline handlers, dangerouslySetInnerHTML patterns, template bindings.
5. Storage use: localStorage/sessionStorage keys, IndexedDB names, service-worker scope.
6. Third-party scripts with their origins, and whether they can influence the DOM.
Clip quotes to 200 characters and cite the asset URL plus capture artifact.
```

**Agent 1e: prior runs and known ground** (only when earlier runs exist)

```text
Read every prior coverage-ledger.json, findings.json, and report in <prior paths>.
For each prior unit and record: the surface it names, its verdict, its fingerprint,
its decisive capture, and what would have to change for that record to be stale.
Then re-fetch the surfaces those records name and report, for each one, whether the
current response still matches the old capture's evidence.
Return a table of: prior fingerprint, current state (same/changed/unknown), and the
unit that should carry it forward. Do not trust a prior verdict without a new capture.
```

Add focused reconnaissance agents for materially distinct identities, subdomains, or applications that these five do not map. If the budget gate blocks one, seed the unmapped area as a `deferred` unit with the reason and disclose it.

## Prior-run input

Before selecting work, the parent reads every compatible prior ledger and findings file for the same target:

- Compare each prior record's surface, request shape, conditions, and fingerprint against the current site. A prior source ref or date is not evidence that the surface is unchanged.
- Carry an unchanged prior `confirmed` record only after a recon capture reproduces its decisive observation; link it to a current `planned` unit with `prior_status: "prior_confirmed_same_scope"` and let a fresh verifier re-capture it.
- If the surface changed but the root cause may survive, create a `prior_confirmed_changed_scope` revalidation unit; do not exclude that root cause from hunting.
- Prior `needs_validation`, `deferred`, `blocked`, and `out_of_scope` units are current work.
- A prior `rejected` claim suppresses only that exact claim while its evidence is unchanged.
- Record missing or unreadable ledgers; do not treat them as empty coverage.

## Architecture summary

The parent writes `<output-dir>/architecture.md`, hard-capped at about 1,000 words, containing:

1. Product, visible roles, protected resources, and the ordinary trust-sensitive actions.
2. Origins in scope, hosting and edge in front of them, and what the edge already enforces.
3. Observed stack and versions, with the marker that revealed them.
4. Entry surfaces and the important request shapes, including auth surfaces and APIs.
5. Trust boundaries and the strongest observed control on each.
6. Identities available to this run and what each can reach.
7. Prior coverage gaps and carried records.
8. A companion-selection summary from [ATTACK-CLASSES.md](ATTACK-CLASSES.md): selected files and the observed surface that requires them.

Keep per-unit block maps in the ledger, not here, so the architecture cap survives large runs.

## Companion selection

Select a companion because reconnaissance observed the boundary its `When to use this file` section describes, not because the site mentions the technology. Select `CACHE-AND-PROXY.md` when a CDN or cache header is visible; `AUTH-AND-SESSION.md` when a login exists; `API-AND-GRAPHQL.md` when a JSON or GraphQL surface responds; and so on. Do not exclude a visible boundary because another agent covers a related class.

## Deterministic coverage ledger

The parent writes `<output-dir>/coverage-ledger.json` as a top-level JSON array. One unit per material combination of surface, boundary, subsystem, and attack class, at the granularity the profile sets.

Each dimension has a human label and a stable observed value in `canonical_refs`:

- `surface`: the request shape, e.g. `POST https://coffee.example/api/session` or the named endpoint group `https://coffee.example/api/orders`.
- `boundary`: the control being tested, e.g. `cookie scope on the session cookie` or `order ownership check`.
- `subsystem`: the application area, e.g. `authentication`, `checkout`, `admin`.
- `attack_class`: `ATTACK-CLASSES.md#` plus the exact class name, or a companion `FILE.md#` plus the exact class name.

Derive `coverage_id` exactly as before, with no lossy slugs:

1. Require each reference to be NFC, valid Unicode scalars, visible, free of control/format/separator/default-ignorable code points, and trimmed.
2. Encode its UTF-8 bytes with RFC 3986 percent encoding, leaving only `A-Z a-z 0-9 - . _ ~` unescaped and using uppercase `%HH`.
3. Join encoded `surface`, `boundary`, `subsystem`, `attack_class` with `::`, appending encoded `lifecycle` when present.

Use the fixed subsystem value `profile/quick/all-in-scope-subsystems` for a `quick` run. Never include a wave, agent, verdict, severity, or timestamp in a reference. Sort by `coverage_id`; fail on duplicates. The validator also rejects one semantic tuple carried by two different references.

Each unit has this shape:

```json
{
  "coverage_id": "...",
  "canonical_refs": {
    "surface": "POST https://coffee.example/api/session",
    "boundary": "session cookie scope",
    "subsystem": "authentication",
    "attack_class": "AUTH-AND-SESSION.md#Session fixation"
  },
  "surface": "Session creation",
  "boundary": "Session cookie scope",
  "subsystem": "Authentication",
  "attack_class": "Session fixation",
  "entry_points": ["POST https://coffee.example/api/session"],
  "ordinary_attack_class_block": "ATTACK-CLASSES.md#Authentication and session",
  "selected_companion_blocks": ["AUTH-AND-SESSION.md#Core discipline"],
  "excluded_blocks": [{"block": "CACHE-AND-PROXY.md#Cache deception", "reason": "no cache headers on this response"}],
  "prior_status": "none",
  "attempts": [],
  "wave": 1,
  "status": "planned",
  "agent_id": null,
  "reviewed_surfaces": [],
  "checks": [],
  "result_fingerprints": [],
  "unresolved": []
}
```

`entry_points` and `reviewed_surfaces` are live references: an absolute `http(s)` URL, optionally prefixed by the method (`GET https://...`). A repository path, a bare `/login`, or a relative URL is invalid.

Each `checks` entry is one observed check:

```json
{
  "agent_id": "hunter-session-1",
  "reviewed_surfaces": ["GET https://coffee.example/login", "POST https://coffee.example/api/session"],
  "invariant": "a new session identifier is issued when the password is verified",
  "method": "active",
  "result": "Set-Cookie returned the pre-login value; the body's CSRF token changed",
  "artifact": "agents/hunter-session-1/artifacts/login-before-after.json"
}
```

`method` is `passive` (a normal fetch the site would serve anyway) or `active` (a crafted request this run made). Every check needs a capture owned by the same agent: `agents/<agent_id>/artifacts/<label>.json`, where the label matches `^[a-z0-9][a-z0-9-]{0,63}$`. A check without a capture is not coverage.

Enforce this state table exactly:

| Status | Unit `agent_id` | `reviewed_surfaces` / `checks` | `result_fingerprints` | `unresolved` |
|---|---|---|---|---|
| `planned` | null | empty | empty | empty |
| `not_applicable`, `out_of_scope`, `deferred` | null | empty | empty | nonempty reason |
| `in_progress` | canonical owner | empty | empty | empty |
| `blocked` | canonical owner | both nonempty owned evidence | empty | nonempty blocker |
| `covered` | canonical owner | both nonempty | empty | empty |
| `candidate` | canonical owner | both nonempty | nonempty | optional |

Canonical agent IDs match `^[a-z0-9][a-z0-9_-]{0,63}$` and are not Windows device names. A unit's `reviewed_surfaces` is exactly the union of its checks' surfaces. `attempts` is the append-only archive written when a coverage critic reopens an evidence-bearing unit; each archived attempt keeps its own owner, captures, and state, and the next assignment increments `wave` with a fresh owner.

Run the validator after seeding, after every parent update, and before Phase 6:

```bash
node <skill-dir>/validate-coverage-ledger.cjs <output-dir>/coverage-ledger.json
```

It rejects input beyond 5 MiB, 64 nesting levels, 10,000 units, 1,000 collection entries, 1,000 object fields, or 500,000 traversed values, and caps reported errors at 100. Fix every error before assigning work or claiming coverage.

The ledger is the coverage claim. A folder of captures, an agent count, or a sentence like "headers reviewed" is not coverage evidence.
