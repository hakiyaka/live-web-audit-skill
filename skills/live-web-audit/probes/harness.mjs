#!/usr/bin/env node
// live-web-audit probe harness: one bounded request at a time, one capture per request.
//
// Usage: node harness.mjs <command> [options]
//   capture --url URL [--method GET] [--header 'A: B']... [--body TEXT]
//           [--label NAME] [--out FILE] [--scope FILE] [--timeout MS] [--max-bytes N]
//   verify  --file CAPTURE.json [--scope FILE]
//   headers | cookies | cors | methods | redirect | cache | fingerprint  --url URL
//   tls --host HOST [--port 443]      dns --host HOST
//   robots --url ORIGIN               sitemap --url ORIGIN
//
// Every network command accepts --out FILE and writes its captures there, so a check
// can always be cited later. Output on stdout is JSON.

import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import dns from "node:dns/promises";
import fs from "node:fs";
import path from "node:path";

import {
  DEFAULTS,
  REDACTED,
  analyzeCookies,
  analyzeHeaders,
  cacheAssessment,
  captureObservation,
  captureSkeleton,
  corsAssessment,
  excerpt,
  fingerprintBody,
  getHeader,
  matchesScope,
  redactHeaders,
  redactUrl,
  scopeAllowsMethod,
} from "./lib.mjs";

const MAX_CAPTURE_BYTES = 1024 * 1024;
const MAX_BODY_BYTES = 8 * 1024;

class HarnessError extends Error {}

function parseArgs(argv) {
  const options = { headers: [] };
  for (let index = 0; index < argv.length; index++) {
    const token = argv[index];
    if (!token.startsWith("--")) throw new HarnessError(`unexpected argument ${token}`);
    const key = token.slice(2);
    if (key === "help") {
      options.help = true;
      continue;
    }
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) throw new HarnessError(`--${key} needs a value`);
    index++;
    if (key === "header") options.headers.push(value);
    else options[key] = value;
  }
  return options;
}

function numberOption(options, name, fallback, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (!(name in options)) return fallback;
  const value = Number(options[name]);
  if (!Number.isFinite(value) || value < min || value > max) throw new HarnessError(`--${name} must be a number between ${min} and ${max}`);
  return value;
}

function loadScope(scopePath) {
  if (!scopePath) return null;
  const text = fs.readFileSync(scopePath, "utf8");
  const scope = JSON.parse(text);
  if (!scope || typeof scope !== "object" || !Array.isArray(scope.in_scope)) {
    throw new HarnessError("scope file must contain an in_scope array");
  }
  return scope;
}

let lastRequestAt = 0;

async function pace(requestsPerSecond) {
  const minimum = Math.ceil(1000 / requestsPerSecond);
  const wait = lastRequestAt + minimum - Date.now();
  if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
  lastRequestAt = Date.now();
}

function headerLines(rawHeaders) {
  const lines = [];
  for (let index = 0; index < rawHeaders.length; index += 2) {
    lines.push(`${rawHeaders[index]}: ${rawHeaders[index + 1]}`);
  }
  return redactHeaders(lines);
}

function requestOnce(urlString, options) {
  const target = new URL(urlString);
  const transport = target.protocol === "https:" ? https : target.protocol === "http:" ? http : null;
  if (!transport) throw new HarnessError(`unsupported protocol ${target.protocol}`);
  const headers = {};
  for (const line of options.headers) {
    const colon = line.indexOf(":");
    if (colon < 1) throw new HarnessError(`--header must look like 'Name: value' (got ${line})`);
    headers[line.slice(0, colon).trim()] = line.slice(colon + 1).trim();
  }
  if (!Object.keys(headers).some((name) => name.toLowerCase() === "user-agent")) headers["User-Agent"] = options.userAgent;

  return new Promise((resolve, reject) => {
    const startedAt = process.hrtime.bigint();
    const request = transport.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || (target.protocol === "https:" ? 443 : 80),
      path: `${target.pathname}${target.search}`,
      method: options.method,
      headers,
      servername: target.protocol === "https:" ? target.hostname : undefined,
      timeout: options.timeoutMs,
    });
    request.on("timeout", () => request.destroy(new HarnessError(`request timed out after ${options.timeoutMs} ms`)));
    request.on("error", reject);
    request.on("response", (response) => {
      const chunks = [];
      let received = 0;
      let truncated = false;
      response.on("data", (chunk) => {
        received += chunk.length;
        if (received <= options.maxBytes) chunks.push(chunk);
        else {
          truncated = true;
          const remaining = options.maxBytes - (received - chunk.length);
          if (remaining > 0) chunks.push(chunk.subarray(0, remaining));
          response.destroy();
        }
      });
      const finish = () => {
        const body = Buffer.concat(chunks);
        const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
        resolve({
          request: {
            method: options.method,
            url: redactUrl(target.toString(), options.secretParams),
            headers: redactHeaders(Object.entries(headers).map(([name, value]) => `${name}: ${value}`)),
            ...(options.body ? { body_excerpt: excerpt(Buffer.from(options.body, "utf8"), 1024) } : {}),
          },
          response: {
            status: response.statusCode,
            headers: headerLines(response.rawHeaders),
            body_excerpt: excerpt(body, options.excerptBytes),
            body_bytes: received,
            truncated,
            content_type: response.headers["content-type"] || null,
          },
          timings: { total_ms: Math.round(elapsedMs) },
        });
      };
      response.on("end", finish);
      response.on("close", finish);
      response.on("error", finish);
    });
    if (options.body) request.write(options.body);
    request.end();
  });
}

async function perform(urlString, options) {
  const hops = [];
  let current = urlString;
  let result = null;
  for (let attempt = 0; attempt <= options.maxRedirects; attempt++) {
    assertInScope(current, options.scope);
    await pace(options.requestsPerSecond);
    result = await requestOnce(current, options);
    const location = getHeader(result.response.headers, "location");
    if (!location || ![301, 302, 303, 307, 308].includes(result.response.status) || attempt === options.maxRedirects) break;
    const nextUrl = new URL(location, current).toString();
    hops.push({ from: redactUrl(current, options.secretParams), status: result.response.status, location: redactUrl(nextUrl, options.secretParams) });
    current = nextUrl;
    if (hops.length > options.maxRedirects) break;
  }
  return { capture: result, redirects: hops };
}

function assertInScope(urlString, scope) {
  if (!scope) return;
  if (!matchesScope(urlString, scope)) throw new HarnessError(`${urlString} is outside the declared scope`);
}

async function capture(url) {
  const options = arguments[1];
  assertInScope(url, options.scope);
  if (!scopeAllowsMethod(options.scope, options.method)) {
    throw new HarnessError(`method ${options.method} is not allowed by the declared scope`);
  }
  const { capture: result, redirects } = await perform(url, options);
  const label = options.label || deriveLabel(url);
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(label)) throw new HarnessError(`label ${label} must match ^[a-z0-9][a-z0-9-]{0,63}$`);
  const skeleton = captureSkeleton({ label, request: result.request, response: result.response, redirects, timings: result.timings });
  const artifactPath = options.out || `agents/${options.agent || "harness"}/artifacts/${label}.json`;
  writeArtifact(artifactPath, skeleton);
  return { artifact: artifactPath, observation: captureObservation(skeleton, artifactPath) };
}

function deriveLabel(urlString) {
  let parsed;
  try {
    parsed = new URL(urlString);
  } catch {
    return "capture";
  }
  const slug = `${parsed.hostname}${parsed.pathname}`
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
  return slug.length > 0 ? slug : "capture";
}

function writeArtifact(artifactPath, payload) {
  const serialized = `${JSON.stringify(payload, null, 2)}\n`;
  if (Buffer.byteLength(serialized) > MAX_CAPTURE_BYTES) throw new HarnessError("capture exceeds the 1 MiB artifact limit");
  fs.mkdirSync(path.dirname(artifactPath), { recursive: true });
  if (fs.existsSync(artifactPath)) throw new HarnessError(`${artifactPath} already exists; captures are never overwritten`);
  fs.writeFileSync(artifactPath, serialized, { flag: "wx" });
}

function verifyCapture(file, scope) {
  const errors = [];
  let payload;
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile()) errors.push("capture must be a regular file");
    if (stat.size > MAX_CAPTURE_BYTES) errors.push("capture exceeds the 1 MiB artifact limit");
    payload = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    return { ok: false, errors: [`capture could not be read: ${error.message}`] };
  }
  if (payload.capture_version !== 1) errors.push("capture_version must be 1");
  if (Array.isArray(payload.captures)) {
    if (payload.captures.length === 0) errors.push("captures must not be empty");
    payload.captures.forEach((entry, index) => verifyOne(entry, `captures[${index}]`, errors, scope));
    return { ok: errors.length === 0, errors, artifact: file, kind: "probe-report", captures: payload.captures.length };
  }
  verifyOne(payload, "capture", errors, scope);
  return { ok: errors.length === 0, errors, artifact: file, kind: "capture" };
}

function verifyOne(payload, prefix, errors, scope) {
  if (typeof payload.label !== "string" || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(payload.label)) errors.push(`${prefix}.label must match ^[a-z0-9][a-z0-9-]{0,63}$`);
  if (typeof payload.observed_at !== "string" || !/^(19|20)[0-9][0-9]-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/.test(payload.observed_at)) {
    errors.push(`${prefix}.observed_at must be an ISO-8601 UTC timestamp with second precision`);
  }
  const request = payload.request;
  if (!request || typeof request !== "object") errors.push(`${prefix}.request is missing`);
  else {
    if (typeof request.method !== "string" || !/^[A-Z]{3,7}$/.test(request.method)) errors.push(`${prefix}.request.method must be an uppercase HTTP method`);
    const urlLooksAbsolute = typeof request.url === "string" && (request.url.startsWith("http://") || request.url.startsWith("https://")) && !/[^!-~]/.test(request.url);
    if (!urlLooksAbsolute) errors.push(`${prefix}.request.url must be an absolute http(s) URL`);
    else if (scope && !matchesScope(request.url, scope)) errors.push(`${prefix}.request.url is outside the declared scope`);
    checkHeaderLines(request.headers, `${prefix}.request.headers`, errors);
  }
  const response = payload.response;
  if (!response || typeof response !== "object") errors.push(`${prefix}.response is missing`);
  else {
    if (!Number.isInteger(response.status) || response.status < 100 || response.status > 599) errors.push(`${prefix}.response.status must be an integer between 100 and 599`);
    checkHeaderLines(response.headers, `${prefix}.response.headers`, errors);
  }
}

function checkHeaderLines(lines, label, errors) {
  if (!Array.isArray(lines)) {
    errors.push(`${label} must be an array`);
    return;
  }
  for (const line of lines) {
    if (typeof line !== "string" || line.indexOf(": ") < 2) {
      errors.push(`${label} contains a line that is not 'Name: value'`);
      continue;
    }
    const name = line.slice(0, line.indexOf(":")).trim().toLowerCase();
    if (["authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"].includes(name) && !line.includes(REDACTED)) {
      errors.push(`${label} leaks an unredacted ${name} value`);
    }
  }
}

async function commandHeaders(url, options) {
  const { capture: result } = await perform(url, options);
  const https = url.startsWith("https:");
  return { url: redactUrl(url, options.secretParams), analysis: analyzeHeaders(result.response.headers, { url, https }), capture: result };
}

async function commandCors(url, options) {
  const origin = options.origin || "https://probe.live-web-audit.example";
  const withOrigin = await perform(url, { ...options, headers: [...options.headers, `Origin: ${origin}`] });
  const withoutOrigin = await perform(url, options);
  return {
    url: redactUrl(url, options.secretParams),
    requestOrigin: origin,
    analysis: corsAssessment({ requestOrigin: origin, headers: withOrigin.capture.response.headers }),
    baseline: corsAssessment({ requestOrigin: origin, headers: withoutOrigin.capture.response.headers }),
    captures: [withOrigin.capture, withoutOrigin.capture],
  };
}

async function commandCache(url, options) {
  const first = await perform(url, options);
  const second = await perform(url, options);
  const firstAssessment = cacheAssessment(first.capture.response.headers);
  const secondAssessment = cacheAssessment(second.capture.response.headers);
  return {
    url: redactUrl(url, options.secretParams),
    first: firstAssessment,
    second: secondAssessment,
    ageAdvanced: firstAssessment.cdnHints.age !== secondAssessment.cdnHints.age,
    captures: [first.capture, second.capture],
  };
}

async function commandRedirect(url, options) {
  const { capture: result, redirects } = await perform(url, options);
  return { url: redactUrl(url, options.secretParams), redirects, finalStatus: result.response.status, captures: [result] };
}

async function commandMethods(url, options) {
  const results = [];
  for (const method of ["OPTIONS", "GET"]) {
    if (!scopeAllowsMethod(options.scope, method)) continue;
    const { capture: result } = await perform(url, { ...options, method });
    results.push({ method, status: result.response.status, allow: getHeader(result.response.headers, "allow"), capture: result });
  }
  return { url: redactUrl(url, options.secretParams), results, captures: results.map((entry) => entry.capture) };
}

async function commandFingerprint(url, options) {
  const { capture: result } = await perform(url, options);
  const body = result.response.body_excerpt || "";
  return {
    url: redactUrl(url, options.secretParams),
    fingerprint: {
      technologies: fingerprintBody(body),
      server: getHeader(result.response.headers, "server"),
      poweredBy: getHeader(result.response.headers, "x-powered-by"),
      generator: (/(<meta[^>]+name=["']generator["'][^>]*>)/i.exec(body) || [])[1] || null,
      contentType: result.response.content_type,
    },
    capture: result,
  };
}

async function commandRobots(url, options) {
  const origin = new URL(url).origin;
  const { capture: result } = await perform(`${origin}/robots.txt`, options);
  const text = result.response.body_excerpt || "";
  const sitemaps = [];
  for (const line of text.split("\n")) {
    const match = /^sitemap:\s*(\S+)/i.exec(line.trim());
    if (match) sitemaps.push(match[1]);
  }
  return { robots_url: `${origin}/robots.txt`, status: result.response.status, sitemaps, body_excerpt: text.slice(0, 1024), capture: result };
}

async function commandSitemap(url, options) {
  const origin = new URL(url).origin;
  const { capture: result } = await perform(`${origin}/sitemap.xml`, options);
  const text = result.response.body_excerpt || "";
  const locations = [...text.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1]).slice(0, 50);
  return { sitemap_url: `${origin}/sitemap.xml`, status: result.response.status, count: locations.length, locations, capture: result };
}

function commandTls(host, port) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false }, () => {
      const certificate = socket.getPeerCertificate();
      const result = {
        host,
        port,
        protocol: socket.getProtocol(),
        cipher: socket.getCipher()?.name || null,
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
        alpnProtocol: socket.alpnProtocol || null,
        subject: certificate?.subject || null,
        issuer: certificate?.issuer || null,
        validFrom: certificate?.valid_from || null,
        validTo: certificate?.valid_to || null,
        serialNumber: certificate?.serialNumber || null,
        subjectAltName: certificate?.subjectaltname || null,
        fingerprint256: certificate?.fingerprint256 || null,
      };
      socket.end();
      resolve(result);
    });
    socket.setTimeout(DEFAULTS.timeoutMs, () => socket.destroy(new HarnessError("TLS handshake timed out")));
    socket.on("error", reject);
  });
}

async function commandDns(host) {
  const results = { host };
  for (const record of ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA"]) {
    try {
      results[record] = await dns.resolve(host, record);
    } catch (error) {
      results[record] = { error: error.code || error.message };
    }
  }
  return results;
}

function commandHelp() {
  return {
    commands: {
      capture: "--url URL [--method GET] [--header 'A: B'] [--body TEXT] [--label NAME] [--out FILE]",
      verify: "--file CAPTURE.json",
      headers: "--url URL",
      cookies: "--url URL",
      cors: "--url URL [--origin https://probe.example]",
      cache: "--url URL",
      redirect: "--url URL",
      methods: "--url URL",
      fingerprint: "--url URL",
      robots: "--url URL",
      sitemap: "--url URL",
      tls: "--host HOST [--port 443]",
      dns: "--host HOST",
    },
    global: "--scope FILE --timeout MS --max-bytes N --max-redirects N --rps N --agent ID",
  };
}

async function main(argv) {
  const [command, ...rest] = argv;
  if (!command || command === "--help") { process.stdout.write(JSON.stringify(commandHelp(), null, 2) + String.fromCharCode(10)); return null; }
  const options = parseArgs(rest);
  if (options.help) {
    process.stdout.write(`${JSON.stringify(commandHelp(), null, 2)}
`);
    return null;
  }
  options.scope = loadScope(options.scope);
  options.timeoutMs = numberOption(options, "timeout", DEFAULTS.timeoutMs, { min: 100, max: 120000 });
  options.maxBytes = numberOption(options, "max-bytes", DEFAULTS.maxBytes, { min: 256, max: 16 * 1024 * 1024 });
  options.excerptBytes = numberOption(options, "excerpt-bytes", DEFAULTS.excerptBytes, { min: 64, max: MAX_BODY_BYTES });
  options.maxRedirects = numberOption(options, "max-redirects", DEFAULTS.maxRedirects, { min: 0, max: 10 });
  options.requestsPerSecond = numberOption(options, "rps", DEFAULTS.requestsPerSecond, { min: 0.1, max: 10 });
  options.userAgent = options["user-agent"] || DEFAULTS.userAgent;
  options.method = (options.method || "GET").toUpperCase();
  options.origin = options.origin;

  const url = options.url;
  const needUrl = () => {
    if (!url) throw new HarnessError(`${command} needs --url`);
    assertInScope(url, options.scope);
  };

  let result;
  switch (command) {
    case "capture":
      needUrl();
      result = await capture(url, options);
      break;
    case "verify": {
      if (!options.file) throw new HarnessError("verify needs --file");
      result = verifyCapture(options.file, options.scope);
      if (!result.ok) process.exitCode = 1;
      break;
    }
    case "headers":
    case "cookies": {
      needUrl();
      const outcome = await commandHeaders(url, options);
      result = command === "cookies" ? { url: outcome.url, cookies: outcome.analysis.cookies, capture: outcome.capture } : outcome;
      break;
    }
    case "cors":
      needUrl();
      result = await commandCors(url, options);
      break;
    case "cache":
      needUrl();
      result = await commandCache(url, options);
      break;
    case "redirect":
      needUrl();
      result = await commandRedirect(url, options);
      break;
    case "methods":
      needUrl();
      result = await commandMethods(url, options);
      break;
    case "fingerprint":
      needUrl();
      result = await commandFingerprint(url, options);
      break;
    case "robots":
      needUrl();
      result = await commandRobots(url, options);
      break;
    case "sitemap":
      needUrl();
      result = await commandSitemap(url, options);
      break;
    case "tls": {
      if (!options.host) throw new HarnessError("tls needs --host");
      const port = numberOption(options, "port", 443, { min: 1, max: 65535 });
      result = await commandTls(options.host, port);
      break;
    }
    case "dns": {
      if (!options.host) throw new HarnessError("dns needs --host");
      result = await commandDns(options.host);
      break;
    }
    default:
      throw new HarnessError(`unknown command ${command}`);
  }

  const collected = result && Array.isArray(result.captures)
    ? result.captures
    : result && result.capture
      ? [result.capture]
      : null;
  if (options.out && collected && collected.length > 0) {
    const normalized = collected.map((entry) => captureSkeleton({
      label: entry.label || deriveLabel((entry.request && entry.request.url) || url || "capture"),
      request: entry.request,
      response: entry.response,
      redirects: entry.redirects || [],
      timings: entry.timings || {},
    }));
    writeArtifact(options.out, { capture_version: 1, command, target: redactUrl(url || options.host || "", options.secretParams), captures: normalized });
    result.artifact = options.out;
  }

  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  return result;
}

main(process.argv.slice(2)).catch((error) => {
  process.stdout.write(`${JSON.stringify({ error: error instanceof HarnessError ? error.message : String(error && error.message ? error.message : error) }, null, 2)}\n`);
  process.exitCode = 2;
});
