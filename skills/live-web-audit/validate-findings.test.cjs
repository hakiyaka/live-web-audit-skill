const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const schema = require("./report-schema.json");
const findings = require("./validate-findings.cjs");

const validatorPath = path.join(__dirname, "validate-findings.cjs");
const CLI_TIMEOUT_MS = 15000;
const NL = String.fromCharCode(10);

function observation(overrides = {}) {
  return {
    label: "login response headers",
    artifact: "agents/hunter-one/artifacts/login-headers.json",
    observed_at: "2026-11-17T10:00:00Z",
    request: {
      method: "GET",
      url: "https://coffee.example/login",
      headers: ["User-Agent: live-web-audit/1.0.0"],
    },
    response: {
      status: 200,
      headers: [
        "Content-Type: text/html; charset=utf-8",
        "Set-Cookie: session=<redacted>; Path=/; HttpOnly",
      ],
    },
    ...overrides,
  };
}

function confirmed(overrides = {}) {
  return {
    verdict: "confirmed",
    fingerprint: "coffee.example/login-session-fixation",
    title: "Session identifier is not rotated at login",
    description: "The Set-Cookie value after authentication equals the pre-login value.",
    root_cause: "The login handler writes the pre-authentication session id into the authenticated session.",
    intended_behavior: "A new session identifier is issued on every privilege change.",
    surface: "https://coffee.example/login",
    attack_class: "Session fixation",
    observations: [observation()],
    conditions: [{ kind: "authentication_level", description: "a victim visits the attacker-chosen session first" }],
    reproduction: {
      actor: "anonymous visitor",
      steps: ["fetch /login and store the session cookie", "authenticate with the wrong password once", "compare the Set-Cookie value"],
      request: "curl -sS -D - -o /dev/null https://coffee.example/login",
      observed_result: "the same session value is returned before and after the login POST",
    },
    remediation: {
      strategy: "Regenerate the server-side session and issue a new cookie inside the successful login branch.",
      changes: [{ location: "/login handler, after credential verification", change: "rotate the session id and re-send the cookie" }],
    },
    severity: {
      likelihood: { score: "high", reason: "an attacker can hand a victim a prepared session link" },
      impact: { score: "medium", reason: "the attacker reads the victim's authenticated pages" },
      overall_severity: "medium",
    },
    confidence: { score: "high", reason: "two captures show the identical pre- and post-login value" },
    ...overrides,
  };
}

function needsValidation(overrides = {}) {
  return {
    verdict: "needs_validation",
    fingerprint: "coffee.example/account-idor",
    title: "Order lookup may not bind the order to the session user",
    description: "A second test identity was unavailable, so the cross-account read could not be captured.",
    claimed_root_cause: "GET /api/orders/{id} returns any order for an authenticated session.",
    surface: "https://coffee.example/api/orders/1001",
    attack_class: "Insecure direct object reference",
    observations: [observation({ request: { method: "GET", url: "https://coffee.example/api/orders/1001" }, response: { status: 200 } })],
    blockers: ["one authenticated test identity was available in this run"],
    validation_plan: { next_probe: "repeat the request with a second test account and compare order ids" },
    ...overrides,
  };
}

function rejected(overrides = {}) {
  return {
    verdict: "rejected",
    fingerprint: "coffee.example/cache-poisoning",
    title: "Reflected X-Forwarded-Host was proposed as cache poisoning",
    description: "The host header is reflected in a debug header only.",
    claimed_root_cause: "the edge caches a response keyed on X-Forwarded-Host",
    surface: "https://coffee.example/",
    attack_class: "Web cache poisoning",
    observations: [observation({ request: { method: "GET", url: "https://coffee.example/", headers: ["X-Forwarded-Host: probe.example"] } })],
    reason: "the reflected value appears in a response header that the edge does not use for routing or storage",
    ...overrides,
  };
}

function errorsFor(document) {
  return findings.validateDocument(document, schema);
}

function tempFile(contents) {
  const file = path.join(os.tmpdir(), `lwa-findings-${process.pid}-${Math.random().toString(16).slice(2)}.json`);
  fs.writeFileSync(file, contents);
  return file;
}

function runCli(file) {
  return spawnSync(process.execPath, [validatorPath, file], { encoding: "utf8", timeout: CLI_TIMEOUT_MS });
}

test("schema has exactly three verdict branches", () => {
  assert.equal(schema.type, "array");
  assert.equal(schema.items.oneOf.length, 3);
  assert.deepEqual(findings.collectSchemaErrors(schema), []);
});

test("accepts an empty document and each complete branch", () => {
  assert.deepEqual(errorsFor([]), []);
  const document = [confirmed(), needsValidation(), rejected()].sort((left, right) => (left.fingerprint < right.fingerprint ? -1 : 1));
  assert.deepEqual(errorsFor(document), []);
});

test("names the failing field through the verdict discriminator", () => {
  const broken = confirmed({ confidence: { score: "certain", reason: "the capture is unambiguous" } });
  const messages = errorsFor([broken]).join(NL);
  assert.match(messages, /confidence[.]score/);
  assert.match(messages, /invalid value/);
});

test("requires fingerprints to be unique and sorted", () => {
  const first = confirmed({ fingerprint: "coffee.example/b" });
  const second = confirmed({ fingerprint: "coffee.example/a" });
  const duplicate = confirmed({ fingerprint: "coffee.example/b" });
  const messages = errorsFor([first, second, duplicate]).join(NL);
  assert.match(messages, /sorted lexicographically/);
  assert.match(messages, /duplicate of/);
});

test("rejects severity above demonstrated impact", () => {
  const finding = confirmed({
    severity: {
      likelihood: { score: "high", reason: "easy to trigger" },
      impact: { score: "low", reason: "one debug value" },
      overall_severity: "critical",
    },
  });
  assert.match(errorsFor([finding]).join(NL), /cannot exceed demonstrated impact/);
});

test("requires a promoted capture for every confirmed observation", () => {
  const foreign = confirmed({ observations: [observation({ artifact: "agents/hunter-two/artifacts/login.json" })] });
  const traversal = confirmed({ observations: [observation({ artifact: "agents/hunter-one/artifacts/../login.json" })] });
  const wrongName = confirmed({ observations: [observation({ artifact: "agents/hunter-one/artifacts/Login Headers.json" })] });
  const withoutCapture = confirmed({ observations: [] });
  const messages = errorsFor([foreign, traversal, wrongName, withoutCapture].sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : 1))).join(NL);
  assert.match(messages, /at least one capture/);
  assert.match(messages, /promoted capture/);
});

test("rejects one capture cited twice", () => {
  const finding = confirmed({ observations: [observation(), observation({ label: "same capture again" })] });
  assert.match(errorsFor([finding]).join(NL), /duplicate of observations\[0\]/);
});

test("requires credential-bearing headers to carry no secret", () => {
  const finding = confirmed({
    observations: [observation({ response: { status: 200, headers: ["Set-Cookie: session=abc123; Path=/; HttpOnly"] } })],
  });
  assert.match(errorsFor([finding]).join(NL), /must carry "<redacted>"/);
});

test("rejects malformed header lines and credential URLs", () => {
  const badHeader = confirmed({ observations: [observation({ request: { method: "GET", url: "https://coffee.example/login", headers: ["X-Probe value without a colon"] } })] });
  const userinfo = confirmed({ observations: [observation({ request: { method: "GET", url: "https://user:pass@coffee.example/login" } })] });
  const messages = errorsFor([badHeader, userinfo].sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : 1))).join(NL);
  assert.match(messages, /single "Name: value"/);
  assert.match(messages, /must not embed credentials/);
});

test("bounds the response status", () => {
  const low = confirmed({ observations: [observation({ response: { status: 99 } })] });
  const high = confirmed({ observations: [observation({ response: { status: 700 } })] });
  const messages = errorsFor([confirmed({ fingerprint: "coffee.example/a" }), { ...high, fingerprint: "coffee.example/b" }]).join(NL);
  assert.match(messages, /between 100 and 599/);
  const lowMessages = errorsFor([low]).join(NL);
  assert.match(lowMessages, /must be at least 100/);
});

test("keeps every verdict's fields separate", () => {
  const withSeverity = needsValidation({ severity: confirmed().severity });
  const emptyPlan = needsValidation({ validation_plan: {} });
  const withPlan = rejected({ validation_plan: { next_probe: "retry the request" } });
  const messages = errorsFor([emptyPlan, withSeverity, withPlan].sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : 1))).join(NL);
  assert.match(messages, /must not contain "severity"/);
  assert.match(messages, /requires at least one visible next_probe or owner_check/);
  assert.match(messages, /must not contain "validation_plan"/);
});

test("requires a replayable reproduction with the full URL", () => {
  const finding = confirmed({ reproduction: { ...confirmed().reproduction, request: "curl -sS /login" } });
  assert.match(errorsFor([finding]).join(NL), /must contain the full request URL/);
});

test("rejects whitespace-only, control, and invalid-scalar prose", () => {
  const blank = confirmed({ title: "   " });
  const control = confirmed({ fingerprint: "coffee.example/control", title: "session\u0007fixation" });
  const surrogate = confirmed({ fingerprint: "coffee.example/surrogate", title: "session\ud800fixation" });
  const messages = errorsFor([blank, control, surrogate].sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : 1))).join(NL);
  assert.match(messages, /visible character|scalar values/);
});

test("passes a complete document through the CLI", () => {
  const file = tempFile(JSON.stringify([confirmed()], null, 2));
  const result = runCli(file);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /PASS: 1 findings valid/);
});

test("reports validation errors without a stack trace and caps them", () => {
  const broken = confirmed({ title: "" });
  const file = tempFile(JSON.stringify([broken]));
  const result = runCli(file);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /^ERROR:/m);
  assert.match(result.stderr, /FAIL: \d+ validation error/);
  assert.doesNotMatch(result.stderr, /at .*:\d+:\d+/);
});

test("fails invalid JSON, an oversized file, and a missing path cleanly", () => {
  const syntax = runCli(tempFile("[}"));
  assert.equal(syntax.status, 1);
  assert.match(syntax.stderr, /Failed to parse findings JSON/);

  const oversized = path.join(os.tmpdir(), `lwa-findings-big-${process.pid}.json`);
  fs.writeFileSync(oversized, `["${"x".repeat(5 * 1024 * 1024 + 16)}"]`);
  const big = runCli(oversized);
  assert.equal(big.status, 1);
  assert.match(big.stderr, /byte limit|exceeds/);

  const missing = runCli(path.join(os.tmpdir(), `lwa-findings-missing-${process.pid}.json`));
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /input could not be opened or read safely|input could not be examined safely/);
});

test("bounds nesting and array size", () => {
  let nested = {};
  for (let depth = 0; depth < 70; depth++) nested = { nested };
  assert.match(errorsFor([nested]).join(NL), /nesting depth/);
  assert.match(errorsFor(Array.from({ length: 1001 }, () => confirmed())).join(NL), /exceeds 1000/);
});

test("rejects unsupported schema keywords", () => {
  const mutated = JSON.parse(JSON.stringify(schema));
  mutated.items.oneOf[0].properties.title.maxLength = 10;
  assert.match(findings.collectSchemaErrors(mutated).join(NL), /unsupported schema keyword/);
});

test("exposes the shared URL and header checks", () => {
  assert.equal(findings.isHttpUrl("https://coffee.example/login"), true);
  assert.equal(findings.isHttpUrl("ftp://coffee.example/login"), false);
  assert.equal(findings.isHeaderLine("Content-Type: text/html"), true);
  assert.equal(findings.isHeaderLine("Content-Type:text/html"), false);
  assert.equal(findings.isObservationArtifact("agents/hunter-one/artifacts/login.json"), true);
});
