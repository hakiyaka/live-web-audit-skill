import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  analyzeCookies,
  analyzeHeaders,
  cacheAssessment,
  captureObservation,
  corsAssessment,
  excerpt,
  fingerprintBody,
  getHeader,
  matchesScope,
  redactHeaderLine,
  redactHeaders,
  redactUrl,
  scopeAllowsMethod,
} from "./lib.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const harness = path.join(here, "harness.mjs");
const HOST = "127.0.0.1";

function runHarness(args) {
  return new Promise((resolve) => {
    execFile(process.execPath, [harness, ...args], { cwd: here, timeout: 30000 }, (error, stdout) => {
      let parsed = null;
      try {
        parsed = JSON.parse(stdout);
      } catch {
        parsed = null;
      }
      resolve({ code: error ? (error.code || 1) : 0, stdout, json: parsed });
    });
  });
}

function tempPath(name) {
  return path.join(os.tmpdir(), `lwa-${process.pid}-${name}`);
}

let context = null;

test.before(async () => {
  const server = http.createServer((request, response) => {
    const origin = `http://${request.headers.host}`;
    const pathname = new URL(request.url, origin).pathname;
    if (pathname === "/") {
      response.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Set-Cookie": ["sid=supersecret; Path=/; HttpOnly; SameSite=Lax"],
        "Cache-Control": "public, max-age=60, s-maxage=600",
        Age: "12",
        "cf-cache-status": "HIT",
      });
      response.end("<meta name=\"generator\" content=\"Coffee 1.0\"><script src=\"/wp-content/x.js\"></script>");
      return;
    }
    if (pathname === "/cookie") {
      response.writeHead(200, { "Set-Cookie": ["sid=abc123; Path=/; SameSite=Lax"] });
      response.end("ok");
      return;
    }
    if (pathname === "/cors") {
      response.writeHead(200, {
        "Access-Control-Allow-Origin": request.headers.origin || "https://fixed.example",
        "Access-Control-Allow-Credentials": "true",
        Vary: "Origin",
      });
      response.end("secret");
      return;
    }
    if (pathname === "/redirect") {
      response.writeHead(302, { Location: "/final" });
      response.end();
      return;
    }
    if (pathname === "/final") {
      response.writeHead(200, { "Content-Type": "text/plain" });
      response.end("final");
      return;
    }
    if (pathname === "/robots.txt") {
      response.writeHead(200, { "Content-Type": "text/plain" });
      response.end("User-agent: *\nDisallow: /admin\nSitemap: http://127.0.0.1/sitemap.xml\n");
      return;
    }
    response.writeHead(404, { "Content-Type": "text/plain" });
    response.end("missing");
  });
  await new Promise((resolve) => server.listen(0, HOST, resolve));
  context = { server, port: server.address().port };
});

test.after(() => {
  if (context) context.server.close();
});

test("redacts credentials while keeping cookie names and flags", () => {
  assert.equal(redactHeaderLine("Authorization: Bearer abc.def.ghi"), "Authorization: Bearer <redacted>");
  assert.equal(redactHeaderLine("Set-Cookie: sid=abc123; Path=/; HttpOnly"), "Set-Cookie: sid=<redacted>; Path=/; HttpOnly");
  assert.equal(redactHeaderLine("Cookie: sid=abc123; theme=dark"), "Cookie: sid=<redacted>; theme=<redacted>");
  assert.equal(redactHeaderLine("Content-Type: text/html"), "Content-Type: text/html");
  assert.deepEqual(redactHeaders(["X-Api-Key: sk_live_1"]), ["X-Api-Key: <redacted>"]);
});

test("redacts secret query parameters and URL userinfo", () => {
  assert.equal(redactUrl("https://coffee.example/reset?token=abc&page=2"), "https://coffee.example/reset?token=%3Credacted%3E&page=2");
  assert.match(redactUrl("https://user:pass@coffee.example/"), /%3Credacted%3E/);
});

test("excerpts a bounded, printable body", () => {
  const input = Buffer.from("a" + String.fromCharCode(7) + "b" + String.fromCharCode(13, 10) + "c", "utf8");
  const text = excerpt(input, 1024);
  assert.equal(text, "a" + String.fromCharCode(92) + "u0007b" + String.fromCharCode(10) + "c");
  const long = excerpt(Buffer.from("x".repeat(50), "utf8"), 10);
  assert.equal(long.length, 10);
});

test("reads cookie flags and cookie-prefix rules", () => {
  const session = analyzeCookies(["sid=abc; Path=/; HttpOnly; SameSite=Lax"], { https: true })[0];
  assert.equal(session.name, "sid");
  assert.equal(session.secure, false);
  assert.equal(session.httpOnly, true);
  assert.equal(session.sameSite, "lax");
  assert.ok(session.notes.some((note) => note.includes("no Secure")));
  const hostCookie = analyzeCookies(["__Host-token=abc; Path=/x; Domain=coffee.example; SameSite=Strict"], { https: true })[0];
  assert.ok(hostCookie.notes.some((note) => note.includes("Path=/")));
  assert.ok(hostCookie.notes.some((note) => note.includes("with Domain")));
});

test("audits response headers as observations, not findings", () => {
  const lines = [
    "Strict-Transport-Security: max-age=31536000",
    "Content-Security-Policy: default-src 'self'; frame-ancestors 'self'",
    "X-Content-Type-Options: nosniff",
    "Server: coffee-edge",
    "Set-Cookie: sid=abc; HttpOnly",
  ];
  const audit = analyzeHeaders(lines, { https: true });
  const byId = Object.fromEntries(audit.checks.map((entry) => [entry.id, entry.state]));
  assert.equal(byId.hsts, "present");
  assert.equal(byId.csp, "present");
  assert.equal(byId.framing, "present");
  assert.equal(byId.nosniff, "present");
  assert.equal(byId["referrer-policy"], "missing");
  assert.equal(byId["disclosure-server"], "present");
  assert.equal(audit.cookies.length, 1);
  assert.equal(getHeader(["X-Test: a", "x-test: b"], "X-TEST"), "a, b");
});

test("classifies CORS responses", () => {
  const headers = ["Access-Control-Allow-Origin: https://evil.example", "Access-Control-Allow-Credentials: true"];
  const reflected = corsAssessment({ requestOrigin: "https://evil.example", headers });
  assert.equal(reflected.verdict, "reflected");
  assert.ok(reflected.notes.some((note) => note.includes("read authenticated responses")));
  const wildcard = corsAssessment({ requestOrigin: "https://evil.example", headers: ["Access-Control-Allow-Origin: *"] });
  assert.equal(wildcard.verdict, "wildcard");
  const none = corsAssessment({ requestOrigin: "https://evil.example", headers: [] });
  assert.equal(none.verdict, "none");
});

test("reads cache policy and CDN hints", () => {
  const cache = cacheAssessment(["Cache-Control: public, s-maxage=600, max-age=60", "Age: 30", "cf-cache-status: HIT"]);
  assert.equal(cache.public, true);
  assert.equal(cache.sMaxAge, 600);
  assert.equal(cache.maxAge, 60);
  assert.equal(cache.cdnHints["cf-cache-status"], "HIT");
  const privateCache = cacheAssessment(["Cache-Control: private, no-store"]);
  assert.equal(privateCache.private, true);
  assert.equal(privateCache.noStore, true);
});

test("identifies technologies from markup", () => {
  const found = fingerprintBody("<meta name=generator content=WordPress><script src=/wp-content/x.js></script>");
  assert.ok(found.some((entry) => entry.tech === "wordpress"));
  assert.deepEqual(fingerprintBody("plain page"), []);
});

test("matches scope by host, subdomain rule, path prefix, and method", () => {
  const scope = {
    in_scope: [{ host: ".coffee.example", path_prefix: "/app", methods: ["GET", "HEAD"] }],
    out_of_scope: ["payments.coffee.example"],
  };
  assert.equal(matchesScope("https://coffee.example/app/orders", scope), true);
  assert.equal(matchesScope("https://admin.coffee.example/app/orders", scope), true);
  assert.equal(matchesScope("https://coffee.example/blog", scope), false);
  assert.equal(matchesScope("https://payments.coffee.example/app/orders", scope), false);
  assert.equal(matchesScope("ftp://coffee.example/app", scope), false);
  assert.equal(scopeAllowsMethod(scope, "GET"), true);
  assert.equal(scopeAllowsMethod(scope, "DELETE"), false);
  assert.equal(scopeAllowsMethod({}, "OPTIONS"), true);
});

test("builds an observation that matches the findings schema", () => {
  const capture = {
    label: "login-headers",
    observed_at: "2026-11-17T10:00:00Z",
    request: { method: "GET", url: "https://coffee.example/login", headers: ["Accept: */*"] },
    response: { status: 200, headers: ["Content-Type: text/html"], body_excerpt: "<html>" },
  };
  const observation = captureObservation(capture, "agents/hunter-one/artifacts/login-headers.json");
  assert.equal(observation.request.method, "GET");
  assert.deepEqual(observation.request.headers, ["Accept: */*"]);
  assert.equal(observation.response.status, 200);
  assert.equal(observation.artifact, "agents/hunter-one/artifacts/login-headers.json");
  const minimal = captureObservation({ ...capture, request: { method: "GET", url: "https://coffee.example/" }, response: { status: 204 } }, "agents/a/artifacts/x.json");
  assert.deepEqual(minimal.response, { status: 204 });
});

test("captures, verifies, and refuses to overwrite", async () => {
  const out = tempPath(`capture-${Date.now()}.json`);
  const url = `http://${HOST}:${context.port}/`;
  const captured = await runHarness(["capture", "--url", url, "--label", "local-home", "--out", out]);
  assert.equal(captured.code, 0);
  assert.equal(captured.json.artifact, out);

  const artifact = JSON.parse(fs.readFileSync(out, "utf8"));
  assert.equal(artifact.capture_version, 1);
  const setCookie = artifact.response.headers.find((line) => line.startsWith("Set-Cookie:"));
  assert.match(setCookie, /sid=<redacted>; Path=\/; HttpOnly/);
  assert.match(artifact.response.body_excerpt, /wp-content/);

  const verified = await runHarness(["verify", "--file", out]);
  assert.equal(verified.code, 0);
  assert.equal(verified.json.ok, true);
  assert.equal(verified.json.kind, "capture");

  const again = await runHarness(["capture", "--url", url, "--label", "local-home", "--out", out]);
  assert.equal(again.code, 2);
  assert.match(again.json.error, /already exists/);
});

test("redacts an authorization header inside the capture", async () => {
  const out = tempPath(`auth-${Date.now()}.json`);
  const url = `http://${HOST}:${context.port}/`;
  const captured = await runHarness(["capture", "--url", url, "--header", "Authorization: Bearer topsecret", "--label", "local-auth", "--out", out]);
  assert.equal(captured.code, 0);
  const text = fs.readFileSync(out, "utf8");
  assert.match(text, /Authorization: Bearer <redacted>/);
  assert.equal(text.includes("topsecret"), false);
});

test("enforces the declared scope and method", async () => {
  const url = `http://${HOST}:${context.port}/`;
  const wrongHost = tempPath(`scope-a-${Date.now()}.json`);
  fs.writeFileSync(wrongHost, JSON.stringify({ in_scope: [{ host: "example.invalid", methods: ["GET"] }] }));
  const outside = await runHarness(["capture", "--url", url, "--scope", wrongHost, "--out", tempPath(`oos-${Date.now()}.json`)]);
  assert.equal(outside.code, 2);
  assert.match(outside.json.error, /outside the declared scope/);

  const getOnly = tempPath(`scope-b-${Date.now()}.json`);
  fs.writeFileSync(getOnly, JSON.stringify({ in_scope: [{ host: HOST, methods: ["GET"] }] }));
  const posted = await runHarness(["capture", "--url", url, "--method", "POST", "--scope", getOnly, "--out", tempPath(`post-${Date.now()}.json`)]);
  assert.equal(posted.code, 2);
  assert.match(posted.json.error, /not allowed by the declared scope/);
});

test("reports header, cookie, cors, cache, redirect, and fingerprint probes", async () => {
  const base = `http://${HOST}:${context.port}`;

  const headerProbe = await runHarness(["headers", "--url", `${base}/`]);
  assert.equal(headerProbe.code, 0);
  const byId = Object.fromEntries(headerProbe.json.analysis.checks.map((entry) => [entry.id, entry.state]));
  assert.equal(byId.hsts, undefined);
  assert.equal(byId.csp, "present");

  const cookieProbe = await runHarness(["cookies", "--url", `${base}/cookie`]);
  assert.equal(cookieProbe.json.cookies[0].secure, false);

  const corsProbe = await runHarness(["cors", "--url", `${base}/cors`, "--origin", "https://evil.example"]);
  assert.equal(corsProbe.json.analysis.verdict, "reflected");
  assert.equal(corsProbe.json.baseline.verdict, "fixed");

  const cacheProbe = await runHarness(["cache", "--url", `${base}/`]);
  assert.equal(cacheProbe.json.first.public, true);

  const redirectProbe = await runHarness(["redirect", "--url", `${base}/redirect`]);
  assert.equal(redirectProbe.json.redirects.length, 1);
  assert.equal(redirectProbe.json.finalStatus, 200);

  const fingerprintProbe = await runHarness(["fingerprint", "--url", `${base}/`]);
  assert.ok(fingerprintProbe.json.fingerprint.technologies.some((entry) => entry.tech === "wordpress"));
  assert.match(fingerprintProbe.json.fingerprint.generator, /Coffee 1[.]0/);

  const robotsProbe = await runHarness(["robots", "--url", `${base}/`]);
  assert.equal(robotsProbe.json.sitemaps.length, 1);
});

test("writes one probe report for a multi-request command", async () => {
  const out = tempPath(`report-${Date.now()}.json`);
  const url = `http://${HOST}:${context.port}/`;
  const cacheProbe = await runHarness(["cache", "--url", url, "--out", out]);
  assert.equal(cacheProbe.code, 0);
  const report = JSON.parse(fs.readFileSync(out, "utf8"));
  assert.equal(report.captures.length, 2);
  const verified = await runHarness(["verify", "--file", out]);
  assert.equal(verified.json.kind, "probe-report");
  assert.equal(verified.json.ok, true);
});

test("rejects a capture with an unredacted cookie", async () => {
  const out = tempPath(`leaky-${Date.now()}.json`);
  fs.writeFileSync(out, JSON.stringify({
    capture_version: 1,
    label: "leaky",
    observed_at: "2026-11-17T10:00:00Z",
    request: { method: "GET", url: `http://${HOST}:${context.port}/` },
    response: { status: 200, headers: ["Set-Cookie: sid=abc123; Path=/"] },
  }));
  const verified = await runHarness(["verify", "--file", out]);
  assert.equal(verified.code, 1);
  assert.equal(verified.json.ok, false);
  assert.match(verified.json.errors.join(" "), /unredacted set-cookie/);
});
