# live-web-audit-skill

A coding-agent skill that turns your agent into a security auditor for a website that is **already running**. You give it a URL; it maps the site from the outside, hunts boundary failures with bounded probes, captures every check as a request/response artifact, and reports findings a second agent has independently replayed.

It is the live counterpart of a source-first audit: instead of tracing code paths, you capture bytes. Every claim carries the exact request, the exact response, and the timestamp behind it.

## What it does

The skill runs a structured audit in six phases:

1. **Reconnaissance** — passive mapping of origins, TLS, headers, cookies, routes, identities, client assets, and third parties, into `architecture.md` and `coverage-ledger.json`.
2. **Coverage-led hunting** — isolated hunters work assigned ledger units and capture every check with the probe harness; coverage critics look for unassigned surfaces.
3. **Candidate validation** — every unique candidate goes to a fresh verifier that re-sends the request and tries to refute it, including cache and identity effects.
4. **Structured output** — `confirmed`, `needs_validation`, and `rejected` records in `findings.json`, validated against `report-schema.json`.
5. **Independent record verification** — fresh agents replay each retained record, check the artifact, the request, and the stated result.
6. **Target-neutral reporting** — `REPORT.md`, `FINDINGS-DETAIL.md`, and `NEEDS-VALIDATION.md`, with copy-pasteable reproducers and edge-versus-application ownership.

The verdicts stay distinct: `confirmed` has a replayed capture and a bounded observed effect, `needs_validation` has one exact missing observation and no severity, `rejected` records a candidate the replay disproved.

## Why "live" needs its own contract

A source audit can cite a line of code. A live audit can only cite a response, so this skill makes the response the unit of evidence:

- **One capture per check.** `probes/harness.mjs` writes a JSON file holding the request (redacted), the response (status, headers, body excerpt), redirects, and timings.
- **No capture, no finding.** A confirmed record cites promoted artifacts under `agents/<agent-id>/artifacts/`; the validator rejects a record that cites anything else.
- **Differential by default.** Configuration claims need two captures: with and without the header, identity A and identity B, first request and cached response.
- **Redaction is enforced.** Cookie, bearer, and API-key values become `<redacted>` before they leave the harness, and the validator rejects an unredacted credential header.
- **Bounded and polite.** One request at a time, one second apart, no load, no brute force, stop on 429 or a challenge page.
- **Scope is a file.** The harness refuses any URL outside `scope.json` and any method the scope does not allow.

## Files

| File | Purpose |
|------|---------|
| `skills/live-web-audit/SKILL.md` | Scope and authorization gate, probing safety, evidence contract, profiles, workflow, anti-patterns |
| `skills/live-web-audit/RECONNAISSANCE.md` | Phase 1 live recon prompts, architecture summary, companion selection, coverage ledger |
| `skills/live-web-audit/HUNTING.md` | Phase 2 hunter prompt template, capture discipline, candidate gate, critic waves |
| `skills/live-web-audit/ATTACK-CLASSES.md` | Core live classes plus pointers to the companion files |
| `skills/live-web-audit/TRANSPORT-AND-HEADERS.md` | HSTS/TLS, cookie attributes, CSP and framing, version disclosure |
| `skills/live-web-audit/AUTH-AND-SESSION.md` | Login, fixation, invalidation, recovery, MFA, JWT/OAuth |
| `skills/live-web-audit/ACCESS-CONTROL.md` | Object ids, roles, tenants, bulk and export scope, CSRF-able actions |
| `skills/live-web-audit/INJECTION-AND-RENDERING.md` | Reflected/stored XSS, SQL/NoSQL, template, command, header injection |
| `skills/live-web-audit/CLIENT-SIDE-AND-JS.md` | Bundles, source maps, DOM sinks, postMessage, storage, service workers |
| `skills/live-web-audit/CACHE-AND-PROXY.md` | Cache keys, deception, private caching, poisoning, normalization |
| `skills/live-web-audit/CORS-AND-CROSS-ORIGIN.md` | Reflected origins, preflight, WebSockets, XS-Leaks |
| `skills/live-web-audit/API-AND-GRAPHQL.md` | Route parity, mass assignment, GraphQL introspection and batching |
| `skills/live-web-audit/FILE-HANDLING-AND-REDIRECTS.md` | Traversal, uploads, archives, open redirects, SSRF fetch targets |
| `skills/live-web-audit/INFO-DISCLOSURE-AND-CONFIG.md` | Debug endpoints, VCS/backup files, source maps, error pages, robots inventory |
| `skills/live-web-audit/AVAILABILITY-AND-RATE-LIMITS.md` | Pre-auth work, amplification, quotas, bounded concurrency |
| `skills/live-web-audit/VALIDATION-AND-REPORTING.md` | Phases 3-6: verifier prompt, findings.json, record verification, reports |
| `skills/live-web-audit/report-schema.json` | JSON schema for all three verdicts |
| `skills/live-web-audit/validate-findings.cjs` | Zero-dependency validator for `findings.json` |
| `skills/live-web-audit/validate-coverage-ledger.cjs` | Zero-dependency validator for the coverage ledger and its canonical IDs |
| `skills/live-web-audit/probes/harness.mjs` | Bounded live probe CLI: capture, verify, headers, cookies, cors, cache, redirect, methods, fingerprint, robots, sitemap, tls, dns |
| `skills/live-web-audit/probes/lib.mjs` | Pure helpers: redaction, header/cookie/CORS/cache analysis, scope matching, fingerprinting |
| `skills/live-web-audit/examples/demo.mjs` | End-to-end demo against a deliberately weak local site; writes `examples/demo-run/` |
| `skills/live-web-audit/examples/scope.json` | A scope file to copy |
| `skills/live-web-audit/examples/run-metadata.json` | Run metadata to copy |

## Install

With the [Skills CLI](https://skills.sh):

```bash
npx skills add https://github.com/<owner>/live-web-audit-skill --skill live-web-audit
```

Add `--global` for a user-level installation. Without the CLI, copy `skills/live-web-audit/` into your agent's skill directory; the skill only needs Node.js.

## Use

Start your agent and name a target:

```
audit https://shop.example.com — we own it, test window until 12:00Z, one test account for each of two tenants
```

```
check the headers, cookies, and CORS policy of https://shop.example.com and tell me what is actually exploitable
```

```
full live audit of https://api.example.com/v1/ with the staging key, output to ~/audits/api
```

The skill activates on "security audit", "pentest this site", "check this URL", and similar requests. A question gets guidance mode; an explicit audit request gets the full workflow, whose output defaults to `~/live-web-audit/<host>/run-<N>`.

## Probe harness

Every network touch goes through the harness, so a check always has an artifact:

```bash
node skills/live-web-audit/probes/harness.mjs capture \
  --url https://shop.example.com/login \
  --scope examples/demo-run/scope.json \
  --label login-headers \
  --out agents/hunter-1/artifacts/login-headers.json

node skills/live-web-audit/probes/harness.mjs headers    --url https://shop.example.com/
node skills/live-web-audit/probes/harness.mjs cookies    --url https://shop.example.com/
node skills/live-web-audit/probes/harness.mjs cors       --url https://shop.example.com/api/me --origin https://probe.example
node skills/live-web-audit/probes/harness.mjs cache      --url https://shop.example.com/
node skills/live-web-audit/probes/harness.mjs redirect   --url https://shop.example.com/login
node skills/live-web-audit/probes/harness.mjs tls        --host shop.example.com
node skills/live-web-audit/probes/harness.mjs verify     --file agents/hunter-1/artifacts/login-headers.json
```

Each command prints JSON. `--out` writes a capture file; `--scope` enforces the declared hosts, paths, and methods; `--rps` caps the request rate; `--timeout`, `--max-bytes`, and `--max-redirects` bound the work.

## Requirements

- Node.js 20 or newer (no dependencies).
- A coding agent with tool use and parallel sub-agents.
- Network access to the target, and an operator who can state the authorization basis.
- Optionally, one or two test identities for authenticated surfaces. Without them, access-control and session claims stay `needs_validation`, and that is a valid result.

## Verify the skill itself

```bash
cd skills/live-web-audit
npm test          # 53 tests: validators, harness, pure helpers
npm run demo      # runs the local demo site and validates a real run directory
```

The demo writes `examples/demo-run/`: a real ledger, real capture artifacts, and a findings file with one reflected-XSS finding, one unauthenticated admin route, and one honest `needs_validation` for a cookie with no reader.

## Design principles

- **A capture is the only evidence.** Memory, a scanner, and a checklist are not.
- **Adversarial replay.** The agent that validates a finding never hunted it.
- **Severity needs an effect.** A missing header is hardening until a reader is named.
- **One request at a time.** The target is production and does not know you are there.
- **Scope is enforced by the tool**, not by good intentions.
- **Several passes beat one.** Coverage is a ledger, not a feeling.

## Credits

Structure, vocabulary, and the coverage-ledger discipline follow Cloudflare's
[`security-audit-skill`](https://github.com/cloudflare/security-audit-skill) (MIT),
adapted from source-first code review to evidence-first work against a live site.

## License

MIT — see [LICENSE](LICENSE).
