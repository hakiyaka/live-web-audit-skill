# Validation, Structured Output, Record Verification, and Reporting

### Phase 3: Independently validate every candidate

After the clean critic pass or a recorded early stop, consolidate Phase 2 candidates and carried records by fingerprint. Give every unique candidate to a fresh `general` verifier that did not hunt it, with its own `agents/<verifier-id>/` root.

A verifier may read the hunter's capture, but must re-send the decisive request itself, capture it again, and compare. It receives the candidate, the linked ledger checks and artifact paths, the scope, the budget, and the confirmed/needs_validation/rejected branches of the schema.

#### Candidate-verifier prompt

```text
You did not write this candidate. Refute it.

1. Re-send the decisive request yourself (harness.mjs capture) and compare with the
   hunter's artifact: same status, same headers, same body evidence. If the response
   differs, decide whether the site changed, the cache answered, or the candidate is
   wrong — and capture what you saw.
2. Verify the identity: was the request really anonymous or really the stated test
   user? Check cookie/token presence and the response's own identity markers.
3. Reconstruct the strongest control that should apply, and look for the one the
   hunter missed: a server-side check, a second path, a WAF, a redirect, a Vary
   header, a SameSite policy, a frame-ancestors directive.
4. For a proposed confirmed record, confirm the observed effect is the one described
   and nothing stronger. Do not extend the test; stop at the same effect.
5. For a proposed needs_validation record, decide whether the blocker is genuinely
   outside this run's reach, and make the next_probe or owner_check exact.
6. Keep the same fingerprint for the same root cause.

Return exactly one JSON object: {"decision": "confirmed|needs_validation|rejected",
"record": { ... }} where record matches that verdict branch of the schema verbatim.
Your capture paths must live under agents/<your-id>/artifacts/.
```

A verifier may promote `needs_validation` to `confirmed` only after its own capture shows the complete path and the effect. It demotes to `needs_validation` when a cache layer, a missing identity, or a browser behaviour makes the decisive step uncertain. It rejects when the replay contradicts the claim, the control is present, or the effect disappears.

Rules the parent applies:

- One final record per fingerprint. If a verifier returns a different fingerprint, it must state a different root cause; otherwise it keeps the original.
- A captured difference that only appears once (A/B test, CDN node, rate limit) is not confirmed until it reproduces.
- A rejected record keeps the verifier's own capture so the next run can see why.
- A malformed or prose-wrapped verifier result is discarded, not repaired; re-run with a fresh verifier when the budget allows, otherwise the unit stays an unvalidated `candidate`.
- Verifier evidence joins the unit's `checks` with the verifier's own `agent_id` and capture; the unit keeps its original assignment owner.

### Phase 4: Write and validate `findings.json`

The parent writes all decided records to `<output-dir>/findings.json`, sorted by fingerprint:

- `confirmed`: captured, replayed violations with conditions, reproduction, remediation, and severity.
- `needs_validation`: captured leads with an exact blocker and one bounded next probe or owner check.
- `rejected`: captured candidates disproved on replay.

Redaction rules are part of the contract: no cookie, bearer token, API key, session value, or personal data appears anywhere in `findings.json`. The validator enforces that credential-bearing header lines carry `<redacted>`.

Then run both validators and fix every error before Phase 5:

```bash
node <skill-dir>/validate-findings.cjs <output-dir>/findings.json
node <skill-dir>/validate-coverage-ledger.cjs <output-dir>/coverage-ledger.json
```

### Phase 5: Independent record verification

Give each retained record to a fresh verifier that did not hunt it and did not validate it in Phase 3 (for `confirmed`, one that did neither). Require one of:

```json
{"decision":"verified","fingerprint":"..."}
```

```json
{"decision":"replace","reason":"...","record":{ }}
```

It checks, in this order:

1. The artifact exists, passes `harness.mjs verify`, and its timestamp is from this run.
2. The artifact's request matches `reproduction.request` and the observation's stated request.
3. The response really shows the claimed status, header, or body evidence — re-fetch to confirm it is still true at verification time.
4. The identity claim is true: the cookie or token used is the stated one, and the response does not silently use another principal.
5. Conditions, severity, and the proposed fix match only what the capture establishes.
6. The fingerprint still names the same root cause as prior and current records.

A replacement that promotes a verdict, changes the root cause, changes the request or observed result, or changes severity is material: give it to another fresh verifier before applying. Non-material wording fixes may be applied directly. After every applied replacement, rerun both validators and update the linked ledger unit.

Set `run_status: "complete"` only when every ledger candidate has an independent final disposition and every retained record passed Phase 5.

### Phase 6: Target-neutral reports from final records

Derive the prose from `findings.json`, the ledger, and the retained `hardening` notes. Prose never changes a verdict, severity, blocker, or observed result.

#### `REPORT.md`

1. Run facts: target, scope, authorization statement, profile, budget with requests and agents used versus planned, observed build, identities used, execution policy (`passive-only`, `live-read-only`, `live-with-test-accounts`), prior-run use, deferred and out-of-scope coverage. A `passive`, `quick`, scoped, budget-limited, or incomplete run says so plainly.
2. One short posture summary.
3. A confirmed-findings table: severity, title, surface, observed result (one line).
4. Each confirmed finding: surface and request, lower-trust actor, reproduction steps, the exact observed result, impact, priority rationale, and the smallest fix with the component that owns it (edge, application, identity provider).
5. A separate `NEEDS VALIDATION` table: title, surface, exact blocker, the bounded next probe or owner check. No severity.
6. Hardening notes, and positive observations worth keeping.
7. Coverage summary: covered, candidate, blocked, deferred counts; the critic result; and what was deliberately not tested.

#### `FINDINGS-DETAIL.md`

For each confirmed `medium`, `high`, or `critical` record: the ordered request sequence, the redacted request/response evidence, the copy-pasteable curl line, the observed result and the invariant it proves, the conditions and containment, and the fix plus a regression check a developer can re-run.

#### `NEEDS-VALIDATION.md`

For every unresolved record: the surface, the capture, the exact blocker, and the bounded next step (with the identity it needs) or the owner check. Keep them as prioritized leads without severity.

Keep the report proportional. A clean run with zero confirmed records is a valid result: say so and state the remaining limits without inventing a low finding.
