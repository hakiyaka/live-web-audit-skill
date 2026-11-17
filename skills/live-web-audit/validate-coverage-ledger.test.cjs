const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const ledger = require("./validate-coverage-ledger.cjs");
const findings = require("./validate-findings.cjs");

const validatorPath = path.join(__dirname, "validate-coverage-ledger.cjs");
const CLI_TIMEOUT_MS = 15000;

// One scenario per route so no two units share a canonical tuple.
function refs(n = 1) {
  return {
    surface: `https://coffee.example/route-${n}`,
    boundary: `cookie/session scope ${n}`,
    subsystem: "auth",
    attack_class: "AUTH-AND-SESSION.md#Session fixation",
  };
}

function surfaceRef(n = 1) {
  return `GET https://coffee.example/route-${n}`;
}

function unit(n = 1, overrides = {}) {
  const canonicalRefs = overrides.canonical_refs || refs(n);
  const base = {
    canonical_refs: canonicalRefs,
    surface: `Route ${n} handler`,
    boundary: `Session cookie scope ${n}`,
    subsystem: "Authentication",
    attack_class: "Session fixation",
    entry_points: [surfaceRef(n)],
    ordinary_attack_class_block: "ATTACK-CLASSES.md#Authentication bypass",
    selected_companion_blocks: [],
    excluded_blocks: [],
    prior_status: "none",
    attempts: [],
    wave: 1,
    status: "planned",
    agent_id: null,
    reviewed_surfaces: [],
    checks: [],
    result_fingerprints: [],
    unresolved: [],
  };
  const merged = { ...base, ...overrides, canonical_refs: canonicalRefs };
  try {
    merged.coverage_id = ledger.canonicalCoverageId(canonicalRefs);
  } catch {
    merged.coverage_id = "invalid-reference";
  }
  return merged;
}

function capture(agentId = "hunter-one", label = "login-headers") {
  return `agents/${agentId}/artifacts/${label}.json`;
}

function check(n = 1, overrides = {}) {
  return {
    agent_id: "hunter-one",
    reviewed_surfaces: [surfaceRef(n)],
    invariant: "session cookie is rotated at login",
    method: "passive",
    result: "Set-Cookie reuses the pre-login value",
    artifact: capture(),
    ...overrides,
  };
}

function covered(n = 1, overrides = {}) {
  return unit(n, {
    status: "covered",
    agent_id: "hunter-one",
    reviewed_surfaces: [surfaceRef(n)],
    checks: [check(n)],
    ...overrides,
  });
}

function candidate(n = 1, overrides = {}) {
  return unit(n, {
    status: "candidate",
    agent_id: "hunter-one",
    reviewed_surfaces: [surfaceRef(n)],
    checks: [check(n)],
    result_fingerprints: ["coffee.example/session-fixation"],
    ...overrides,
  });
}

function sorted(units) {
  return [...units].sort((left, right) => (left.coverage_id < right.coverage_id ? -1 : left.coverage_id > right.coverage_id ? 1 : 0));
}

function errorsFor(value) {
  return ledger.validateDocument(value);
}

function tempFile(contents) {
  const file = path.join(os.tmpdir(), `lwa-ledger-${process.pid}-${Math.random().toString(16).slice(2)}.json`);
  fs.writeFileSync(file, contents);
  return file;
}

function runCli(file) {
  return spawnSync(process.execPath, [validatorPath, file], { encoding: "utf8", timeout: CLI_TIMEOUT_MS });
}

test("accepts an empty ledger", () => {
  assert.deepEqual(errorsFor([]), []);
});

test("derives canonical IDs from exact UTF-8 references", () => {
  assert.equal(ledger.encodeCanonicalRef("a/b c"), "a%2Fb%20c");
  assert.equal(ledger.encodeCanonicalRef("\u00e4"), "%C3%A4");
  assert.match(ledger.canonicalCoverageId(refs(1)), /^https%3A%2F%2Fcoffee[.]example%2Froute-1::cookie%2Fsession%20scope%201::auth::/);
  assert.deepEqual(errorsFor([unit(1)]), []);
});

test("accepts every complete unit state", () => {
  const planned = unit(1);
  const done = covered(2);
  const live = candidate(3);
  const blocked = unit(4, {
    status: "blocked",
    agent_id: "hunter-two",
    reviewed_surfaces: [surfaceRef(4)],
    checks: [check(4, { agent_id: "hunter-two", artifact: capture("hunter-two") })],
    unresolved: ["authenticated session with a second identity was unavailable"],
  });
  const deferred = unit(5, { status: "deferred", unresolved: ["budget_cannot_reserve_critics_and_validation"] });
  const outOfScope = unit(6, { status: "out_of_scope", unresolved: ["identity provider is a third party"] });
  assert.deepEqual(errorsFor(sorted([planned, done, live, blocked, deferred, outOfScope])), []);
});

test("rejects a coverage ID that does not match its references", () => {
  const bad = unit(1);
  bad.coverage_id = "login::cookie::auth::fixation";
  assert.match(errorsFor([bad]).join("\n"), /expected canonical ID/);
});

test("rejects duplicates, collisions, and aliases for one semantic tuple", () => {
  const duplicate = errorsFor(sorted([covered(1), covered(1)])).join(String.fromCharCode(10));
  assert.match(duplicate, /duplicate coverage ID/);

  const collision = errorsFor(sorted([covered(1), covered(1, { boundary: "Another boundary" })])).join(String.fromCharCode(10));
  assert.match(collision, /canonical identity collision/);

  const aliasUnit = unit(2, {
    surface: "Route 1 handler",
    boundary: "Session cookie scope 1",
    subsystem: "Authentication",
    attack_class: "Session fixation",
  });
  const alias = errorsFor(sorted([unit(1), aliasUnit])).join(String.fromCharCode(10));
  assert.match(alias, /semantic tuple already uses coverage ID/);
});

test("requires lexicographic order", () => {
  const units = [covered(2), unit(1)];
  assert.match(errorsFor(units).join("\n"), /sorted lexicographically/);
});

test("enforces state evidence", () => {
  const coveredWithoutChecks = covered(1, { checks: [], reviewed_surfaces: [] });
  const blockedWithoutReason = unit(2, { status: "blocked", agent_id: "hunter-one", reviewed_surfaces: [surfaceRef(2)], checks: [check(2)] });
  const plannedWithOwner = unit(3, { agent_id: "hunter-one" });
  const candidateWithoutFingerprint = candidate(4, { result_fingerprints: [] });
  const messages = errorsFor(sorted([coveredWithoutChecks, blockedWithoutReason, plannedWithOwner, candidateWithoutFingerprint])).join("\n");
  assert.match(messages, /requires entries/);
  assert.match(messages, /planned unit must be unassigned/);
});

test("requires an owned capture for every check", () => {
  const foreign = covered(1, { checks: [check(1, { artifact: capture("hunter-two") })] });
  const none = covered(2, { checks: [check(2, { artifact: null })] });
  const unlabelled = covered(3, { checks: [check(3, { artifact: "agents/hunter-one/artifacts/Login Headers.json" })] });
  const messages = errorsFor(sorted([foreign, none, unlabelled])).join("\n");
  assert.match(messages, /every check needs a capture/);
});

test("rejects two checks citing one capture inside a unit", () => {
  const unitValue = covered(1, {
    reviewed_surfaces: [surfaceRef(1), "GET https://coffee.example/account"],
    checks: [check(1), check(1, { reviewed_surfaces: ["GET https://coffee.example/account"] })],
  });
  assert.match(errorsFor([unitValue]).join("\n"), /capture already cited/);
});

test("keeps reviewed_surfaces equal to the union of check surfaces", () => {
  const extra = covered(1, { reviewed_surfaces: [surfaceRef(1), "GET https://coffee.example/account"] });
  const missing = covered(2, { checks: [check(2, { reviewed_surfaces: [surfaceRef(2), "GET https://coffee.example/account"] })] });
  const messages = errorsFor(sorted([extra, missing])).join("\n");
  assert.match(messages, /has no check owner/);
  assert.match(messages, /is absent from aggregate reviewed_surfaces/);
});

test("accepts only live surface references in entry_points and reviewed_surfaces", () => {
  const sourcePath = unit(1, { entry_points: ["src/routes/login.ts"] });
  const relative = unit(2, { entry_points: ["/login"] });
  const withMethod = unit(3, { entry_points: ["POST https://coffee.example/api/login"] });
  const messages = errorsFor(sorted([sourcePath, relative])).join("\n");
  assert.match(messages, /invalid surface reference/);
  assert.deepEqual(errorsFor([withMethod]), []);
});

test("archives prior evidence when a critic assigns a fresh owner", () => {
  const archived = {
    wave: 1,
    status: "covered",
    agent_id: "hunter-one",
    reviewed_surfaces: [surfaceRef(1)],
    checks: [check(1)],
    result_fingerprints: [],
    unresolved: [],
    reassignment_reason: "critic found an unchecked sibling route",
  };
  assert.deepEqual(errorsFor([unit(1, { wave: 2, status: "in_progress", agent_id: "hunter-two", attempts: [archived] })]), []);
  assert.match(
    errorsFor([unit(1, { wave: 2, status: "in_progress", agent_id: "hunter-one", attempts: [archived] })]).join("\n"),
    /must be fresh after reassignment/,
  );
  assert.match(
    errorsFor([unit(1, { wave: 1, status: "in_progress", agent_id: "hunter-two", attempts: [{ ...archived, wave: 1 }] })]).join("\n"),
    /must precede current wave/,
  );
});

test("rejects control, format, and invalid-scalar prose", () => {
  const control = unit(1, { boundary: "cookie scope\u0007" });
  const format = unit(2, { canonical_refs: { ...refs(2), boundary: "cookie\u200escope 2" } });
  const loneSurrogate = unit(3, { subsystem: "auth\ud800" });
  const messages = errorsFor(sorted([control, format, loneSurrogate])).join("\n");
  assert.match(messages, /invalid text|invalid canonical reference/);
});

test("bounds nesting, array size, and object fields", () => {
  let nested = {};
  for (let depth = 0; depth < 70; depth++) nested = { nested };
  assert.match(errorsFor([nested]).join("\n"), /nesting depth/);

  const wide = unit(1, { unresolved: Array.from({ length: 1001 }, (_value, index) => `reason-${index}`) });
  assert.match(errorsFor([wide]).join("\n"), /exceeds 1000 entries/);
});

test("passes a valid ledger through the CLI", () => {
  const file = tempFile(JSON.stringify(sorted([unit(1), covered(2), candidate(3)]), null, 2));
  const result = runCli(file);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /PASS: 3 coverage units valid/);
});

test("fails malformed JSON, an oversized input, and an unreadable path cleanly", () => {
  const malformed = runCli(tempFile("[{"));
  assert.equal(malformed.status, 1);
  assert.match(malformed.stderr, /Failed to parse coverage ledger/);
  assert.doesNotMatch(malformed.stderr, /at .*:\d+:\d+/);

  const oversized = path.join(os.tmpdir(), `lwa-ledger-big-${process.pid}.json`);
  fs.writeFileSync(oversized, `["${"x".repeat(5 * 1024 * 1024 + 16)}"]`);
  const big = runCli(oversized);
  assert.equal(big.status, 1);
  assert.match(big.stderr, /byte limit|exceeds/);

  const missing = runCli(path.join(os.tmpdir(), `lwa-ledger-missing-${process.pid}.json`));
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /input could not be opened or read safely|input could not be examined safely/);
});

test("rejects a symlinked ledger file", () => {
  const target = tempFile("[]");
  const link = path.join(os.tmpdir(), `lwa-ledger-link-${process.pid}.json`);
  try {
    fs.rmSync(link, { force: true });
    fs.symlinkSync(target, link, "file");
  } catch {
    return;
  }
  const result = runCli(link);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /must not be a symlink/);
});

test("shares capture-path and agent rules with the findings validator", () => {
  assert.equal(ledger.isSafeAgentId("hunter-one"), true);
  assert.equal(ledger.isSafeAgentId("Hunter-One"), false);
  assert.equal(ledger.isSafeAgentId("con"), false);
  assert.equal(findings.isObservationArtifact(capture()), true);
  assert.equal(findings.isObservationArtifact("agents/hunter-one/artifacts/Login.json"), false);
});
