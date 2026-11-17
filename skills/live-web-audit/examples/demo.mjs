#!/usr/bin/env node
// End-to-end demo of the live-web-audit contract against a deliberately weak local site.
// It serves three surfaces, captures every check with the harness, writes a coverage
// ledger and findings.json, then runs both validators.
//
//   node examples/demo.mjs
//
// The output lands in examples/demo-run/ and is committed as a worked example.

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const run = promisify(execFile);
const require = createRequire(import.meta.url);
const { canonicalCoverageId } = require("../validate-coverage-ledger.cjs");

const here = path.dirname(fileURLToPath(import.meta.url));
const skillDir = path.resolve(here, "..");
const runDir = path.join(here, "demo-run");
const harness = path.join(skillDir, "probes", "harness.mjs");
const PORT = 8787;
const ORIGIN = `http://127.0.0.1:${PORT}`;
const AGENT = "hunter-demo";

function server() {
  return http.createServer((request, response) => {
    const url = new URL(request.url, ORIGIN);
    if (url.pathname === "/") {
      response.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Set-Cookie": ["sid=pre-auth-value; Path=/"],
        "Cache-Control": "public, max-age=60",
      });
      response.end("<html><body><h1>Coffee Shop</h1><a href=/admin>Admin</a><form action=/search><input name=q></form></body></html>");
      return;
    }
    if (url.pathname === "/search") {
      const q = url.searchParams.get("q") || "";
      response.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      response.end(`<html><body><p>Results for ${q}</p></body></html>`);
      return;
    }
    if (url.pathname === "/admin") {
      response.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      response.end("<html><body><h1>Admin</h1><p>42 users, 7 refunds pending</p></body></html>");
      return;
    }
    response.writeHead(404, { "Content-Type": "text/html; charset=utf-8" });
    response.end("<html><body>Not found</body></html>");
  });
}

async function harnessRun(args) {
  const { stdout } = await run(process.execPath, [harness, ...args], { cwd: skillDir, encoding: "utf8" });
  return JSON.parse(stdout);
}

async function capture(label, url) {
  const artifact = path.join(runDir, "agents", AGENT, "artifacts", `${label}.json`);
  fs.rmSync(artifact, { force: true });
  const result = await harnessRun([
    "capture",
    "--url",
    url,
    "--scope",
    path.join(runDir, "scope.json"),
    "--label",
    label,
    "--out",
    artifact,
  ]);
  const relative = path.relative(runDir, artifact).split(path.sep).join("/");
  return { artifact: relative, observation: { ...result.observation, artifact: relative } };
}

function unit(n, { surface, surfaceRef, boundary, subsystem, attackClass, block, entryPoints }) {
  const canonical_refs = { surface: surfaceRef, boundary, subsystem, attack_class: attackClass };
  return {
    coverage_id: canonicalCoverageId(canonical_refs),
    canonical_refs,
    surface,
    boundary: boundary.replace(/-/g, " "),
    subsystem,
    attack_class: attackClass.split("#")[1],
    entry_points: entryPoints,
    ordinary_attack_class_block: block,
    selected_companion_blocks: [],
    excluded_blocks: [{ block: "CACHE-AND-PROXY.md#Cache key", reason: "no CDN or shared cache header observed in this demo" }],
    prior_status: "none",
    attempts: [],
    wave: 1,
    status: "covered",
    agent_id: AGENT,
    reviewed_surfaces: entryPoints,
    checks: [],
    result_fingerprints: [],
    unresolved: [],
  };
}

fs.rmSync(runDir, { recursive: true, force: true });
fs.mkdirSync(path.join(runDir, "agents", AGENT, "scratch"), { recursive: true });
fs.mkdirSync(path.join(runDir, "agents", AGENT, "artifacts"), { recursive: true });

const instance = server();
await new Promise((resolve) => instance.listen(PORT, "127.0.0.1", resolve));

try {
  fs.writeFileSync(path.join(runDir, "scope.json"), `${JSON.stringify({
    authorization: "demo: the auditor starts this local server for the run",
    in_scope: [{ host: "127.0.0.1", methods: ["GET", "HEAD", "OPTIONS"] }],
    out_of_scope: [],
    max_rps: 2,
    max_requests: 50,
  }, null, 2)}\n`);

  fs.writeFileSync(path.join(runDir, "run-metadata.json"), `${JSON.stringify({
    run_id: "demo-run-1",
    target: ORIGIN,
    repo: "live-web-audit-skill",
    source_ref: "local demo server, no repository",
    profile: "quick",
    scope_paths: [ORIGIN],
    authorization: "demo: the auditor starts this local server for the run",
    budget: { max_agents: 4, max_requests: 50 },
    execution_policy: "live-read-only",
    selected_companions: ["INJECTION-AND-RENDERING.md", "ACCESS-CONTROL.md", "TRANSPORT-AND-HEADERS.md"],
    prior_runs: [],
    shared_file_owners: ["parent"],
    run_status: "complete",
  }, null, 2)}\n`);

  const architecture = [
    "# Architecture summary",
    "",
    `A three-page local demo shop served over plain HTTP on 127.0.0.1:${PORT}.`,
    "",
    "- **Principals.** Anonymous visitor only. No login exists, so every access-control",
    "  question is asked from the anonymous position.",
    "- **Surfaces.** GET / (home, sets the sid cookie), GET /search?q= (server-rendered",
    "  results), GET /admin (linked from the home page, renders user and refund counts).",
    "- **Stack.** Node.js http module, no framework, no CDN, no cache layer.",
    "- **Controls observed.** No security headers on any response; one cookie with no",
    "  Secure, HttpOnly, or SameSite; /admin returns its body to an anonymous GET.",
    "- **Identities available.** None beyond anonymous.",
    "- **Companions selected.** INJECTION-AND-RENDERING.md (server-rendered q),",
    "  ACCESS-CONTROL.md (unauthenticated admin route), TRANSPORT-AND-HEADERS.md (cookie",
    "  and header posture).",
    "- **Out of scope.** Nothing yet; the demo has three surfaces.",
    "",
  ].join(String.fromCharCode(10));
  fs.writeFileSync(path.join(runDir, "architecture.md"), architecture);

  // Every check is a capture; nothing is cited from memory.
  const home = await capture("home", `${ORIGIN}/`);
  const admin = await capture("admin", `${ORIGIN}/admin`);
  const searchPlain = await capture("search-plain", `${ORIGIN}/search?q=coffee`);
  const searchMarkup = await capture("search-markup", `${ORIGIN}/search?q=%3Cb%3Eprobe%3C%2Fb%3E`);
  const headers = await harnessRun(["headers", "--url", `${ORIGIN}/`, "--scope", path.join(runDir, "scope.json")]);

  const headerState = Object.fromEntries(headers.analysis.checks.map((entry) => [entry.id, entry.state]));

  const units = [
    unit(1, {
      surface: "Search results rendering",
      surfaceRef: `GET ${ORIGIN}/search?q=coffee`,
      boundary: "html-encoding-of-reflected-input",
      subsystem: "search",
      attackClass: "ATTACK-CLASSES.md#Injection",
      block: "ATTACK-CLASSES.md#Injection",
      entryPoints: [`GET ${ORIGIN}/search?q=coffee`],
    }),
    unit(2, {
      surface: "Admin route",
      surfaceRef: `GET ${ORIGIN}/admin`,
      boundary: "anonymous-authorization-on-admin-route",
      subsystem: "admin",
      attackClass: "ATTACK-CLASSES.md#Access control",
      block: "ATTACK-CLASSES.md#Access control",
      entryPoints: [`GET ${ORIGIN}/admin`],
    }),
    unit(3, {
      surface: "Session cookie",
      surfaceRef: `GET ${ORIGIN}/`,
      boundary: "cookie-attributes-and-reader",
      subsystem: "transport",
      attackClass: "TRANSPORT-AND-HEADERS.md#Cookie attributes and scope",
      block: "ATTACK-CLASSES.md#Transport and header configuration",
      entryPoints: [`GET ${ORIGIN}/`],
    }),
  ];

  units[0].checks = [
    {
      agent_id: AGENT,
      reviewed_surfaces: [`GET ${ORIGIN}/search?q=coffee`],
      invariant: "a reflected query value is HTML-encoded before it reaches the body",
      method: "active",
      result: `the marker <b>probe</b> was returned unescaped inside <p>Results for ...</p> (status ${searchMarkup.observation.response.status})`,
      artifact: searchMarkup.artifact,
    },
  ];
  units[0].result_fingerprints = ["127.0.0.1/search-reflected-xss"];
  units[0].status = "candidate";
  units[0].reviewed_surfaces = [`GET ${ORIGIN}/search?q=%3Cb%3Eprobe%3C%2Fb%3E`];
  units[0].checks[0].reviewed_surfaces = units[0].reviewed_surfaces;

  units[1].checks = [
    {
      agent_id: AGENT,
      reviewed_surfaces: [`GET ${ORIGIN}/admin`],
      invariant: "the admin route requires an authenticated privileged identity",
      method: "passive",
      result: `anonymous GET /admin returned ${admin.observation.response.status} with the admin body`,
      artifact: admin.artifact,
    },
  ];
  units[1].result_fingerprints = [
    headerState.framing === "missing" ? "127.0.0.1/admin-unauthenticated" : "127.0.0.1/admin-unauthenticated",
  ];
  units[1].status = "candidate";

  units[2].checks = [
    {
      agent_id: AGENT,
      reviewed_surfaces: [`GET ${ORIGIN}/`],
      invariant: "a session cookie is Secure, HttpOnly, and SameSite-scoped",
      method: "passive",
      result: `Set-Cookie: sid=<redacted>; Path=/ — no Secure, HttpOnly, or SameSite; headers: ${Object.entries(headerState).map(([key, value]) => `${key}=${value}`).join(", ")}`,
      artifact: home.artifact,
    },
  ];
  units[2].status = "candidate";
  units[2].result_fingerprints = ["127.0.0.1/insecure-session-cookie"];

  units.sort((left, right) => (left.coverage_id < right.coverage_id ? -1 : left.coverage_id > right.coverage_id ? 1 : 0));
  fs.writeFileSync(path.join(runDir, "coverage-ledger.json"), `${JSON.stringify(units, null, 2)}\n`);

  const findings = [
    {
      verdict: "confirmed",
      fingerprint: "127.0.0.1/search-reflected-xss",
      title: "Search query is reflected into the HTML body without encoding",
      description: "The value of q is concatenated into the results paragraph, so markup sent by a visitor is returned as markup.",
      root_cause: "The results template interpolates the raw query string into HTML instead of encoding it.",
      intended_behavior: "A query value is encoded for the context it is rendered into, so it appears as text, not markup.",
      surface: `${ORIGIN}/search?q=`,
      attack_class: "Injection",
      observations: [searchMarkup.observation, searchPlain.observation],
      conditions: [{ kind: "user_interaction", description: "a victim follows a crafted search link" }],
      reproduction: {
        actor: "anonymous visitor",
        steps: ["open the crafted search URL", "read the returned body around Results for"],
        request: `curl -sS '${ORIGIN}/search?q=%3Cb%3Eprobe%3C%2Fb%3E'`,
        observed_result: "the response contains <p>Results for <b>probe</b></p>, so the marker is live markup",
      },
      remediation: {
        strategy: "Encode the query value for HTML text at render time (escape <, >, &, \" and ') and add the site's CSP as defence in depth.",
        changes: [{ location: "search results renderer", change: "escape q before interpolation" }],
      },
      severity: {
        likelihood: { score: "high", reason: "the link is a normal GET a victim can be sent" },
        impact: { score: "medium", reason: "script execution in the visitor's origin, no identity involved on this site" },
        overall_severity: "medium",
      },
      confidence: { score: "high", reason: "two captures show the exact unescaped marker in the body" },
    },
    {
      verdict: "confirmed",
      fingerprint: "127.0.0.1/admin-unauthenticated",
      title: "Admin route renders its body for anonymous callers",
      description: "GET /admin returns the administrative page with user and refund counts without any identity.",
      root_cause: "The admin route has no server-side authentication check; the home page hides it only behind a link.",
      intended_behavior: "Only an authenticated administrator receives the admin page.",
      surface: `${ORIGIN}/admin`,
      attack_class: "Access control",
      observations: [admin.observation],
      conditions: [{ kind: "authentication_level", description: "the caller sends no cookie or token" }],
      reproduction: {
        actor: "anonymous visitor",
        steps: ["request /admin without any cookie"],
        request: `curl -sS ${ORIGIN}/admin`,
        observed_result: "status 200 with the body <h1>Admin</h1><p>42 users, 7 refunds pending</p>",
      },
      remediation: {
        strategy: "Enforce the administrator role on the server before rendering /admin, and redirect anonymous callers.",
        changes: [{ location: "GET /admin handler", change: "return 403 unless the session role is admin" }],
      },
      severity: {
        likelihood: { score: "high", reason: "one anonymous request is enough" },
        impact: { score: "medium", reason: "the page discloses aggregate data, not per-user records" },
        overall_severity: "medium",
      },
      confidence: { score: "high", reason: "the anonymous capture returns the admin body" },
    },
    {
      verdict: "needs_validation",
      fingerprint: "127.0.0.1/insecure-session-cookie",
      title: "Session cookie carries no Secure, HttpOnly, or SameSite attribute",
      description: "The site issues sid with Path=/ only. The demo has no TLS and no script injection of its own, so the reader of this cookie is not established here.",
      claimed_root_cause: "The cookie is written without transport, script, or cross-site scoping.",
      surface: `${ORIGIN}/`,
      attack_class: "Cookie attributes and scope",
      observations: [home.observation],
      blockers: ["the demo serves plain HTTP, so Secure cannot be observed in effect", "no script-execution primitive was captured on this site"],
      validation_plan: {
        next_probe: "serve the same page over HTTPS and re-capture Set-Cookie to see whether Secure appears",
        owner_check: "confirm whether production sets Secure, HttpOnly, and SameSite at the edge or in the application",
      },
    },
  ];

  findings.sort((left, right) => (left.fingerprint < right.fingerprint ? -1 : left.fingerprint > right.fingerprint ? 1 : 0));
  fs.writeFileSync(path.join(runDir, "findings.json"), `${JSON.stringify(findings, null, 2)}\n`);

  const findingsCheck = execFileSync(process.execPath, [path.join(skillDir, "validate-findings.cjs"), path.join(runDir, "findings.json")], { encoding: "utf8" });
  const ledgerCheck = execFileSync(process.execPath, [path.join(skillDir, "validate-coverage-ledger.cjs"), path.join(runDir, "coverage-ledger.json")], { encoding: "utf8" });
  process.stdout.write(findingsCheck);
  process.stdout.write(ledgerCheck);
  process.stdout.write(`Wrote ${path.relative(skillDir, runDir)} with ${units.length} units and ${findings.length} records.\n`);
} finally {
  instance.close();
}
