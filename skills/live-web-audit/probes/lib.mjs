// Pure helpers for the live-web-audit probe harness.
// Everything here is offline-testable: no sockets, no filesystem.

export const VERSION = "1.0.0";

export const DEFAULTS = Object.freeze({
  timeoutMs: 10000,
  maxBytes: 2 * 1024 * 1024,
  excerptBytes: 2048,
  maxRedirects: 5,
  requestsPerSecond: 1,
  userAgent: `live-web-audit/${VERSION}`,
});

export const REDACTED = "<redacted>";

export const SECRET_HEADERS = new Set([
  "authorization",
  "cookie",
  "set-cookie",
  "proxy-authorization",
  "x-api-key",
  "x-auth-token",
  "x-csrf-token",
  "x-amz-security-token",
]);

export const DEFAULT_SECRET_PARAMS = Object.freeze([
  "token",
  "key",
  "api_key",
  "apikey",
  "sig",
  "signature",
  "session",
  "password",
  "secret",
  "code",
  "access_token",
  "id_token",
  "auth",
]);

function redactCookiePair(pair) {
  const trimmed = pair.trim();
  const equals = trimmed.indexOf("=");
  if (equals < 0) return trimmed;
  return `${trimmed.slice(0, equals + 1)}${REDACTED}`;
}

function redactSetCookieValue(value) {
  const parts = value.split(";");
  const first = redactCookiePair(parts[0]);
  const attributes = parts.slice(1).map((part) => part.trim()).filter((part) => part.length > 0);
  return [first, ...attributes].join("; ");
}

export function redactHeaderLine(line) {
  const text = String(line);
  const colon = text.indexOf(":");
  if (colon < 1) return text;
  const name = text.slice(0, colon).trim();
  const value = text.slice(colon + 1).trim();
  const lower = name.toLowerCase();
  if (lower === "cookie") {
    const pairs = value.split(";").map((pair) => redactCookiePair(pair)).filter((pair) => pair.length > 0);
    return `${name}: ${pairs.join("; ")}`;
  }
  if (lower === "set-cookie") return `${name}: ${redactSetCookieValue(value)}`;
  if (!SECRET_HEADERS.has(lower)) return `${name}: ${value}`;
  const space = value.indexOf(" ");
  const scheme = space > 0 ? `${value.slice(0, space)} ` : "";
  return `${name}: ${scheme}${REDACTED}`;
}

export function redactHeaders(headers) {
  return (Array.isArray(headers) ? headers : []).map(redactHeaderLine);
}

export function redactUrl(rawUrl, secretParams = DEFAULT_SECRET_PARAMS) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return rawUrl;
  }
  const names = new Set(secretParams.map((name) => name.toLowerCase()));
  for (const name of [...parsed.searchParams.keys()]) {
    if (names.has(name.toLowerCase())) parsed.searchParams.set(name, REDACTED);
  }
  if (parsed.username || parsed.password) {
    parsed.username = REDACTED;
    parsed.password = REDACTED;
  }
  return parsed.toString();
}

// Keep a response body printable and bounded without splitting a multi-byte character.
export function excerpt(buffer, maxBytes = DEFAULTS.excerptBytes) {
  const slice = Buffer.isBuffer(buffer) ? buffer.subarray(0, maxBytes) : Buffer.from(String(buffer), "utf8").subarray(0, maxBytes);
  let text = slice.toString("utf8");
  if (text.endsWith("\ufffd")) text = text.slice(0, -1);
  let out = "";
  for (const character of text) {
    const code = character.codePointAt(0);
    if (code === 9 || code === 10 || code === 13) {
      out += character === "\r" ? "" : character;
    } else if (code < 0x20 || code === 0x7f) {
      out += `\\u${code.toString(16).padStart(4, "0")}`;
    } else {
      out += character;
    }
  }
  return out;
}

// Cookie names and flags survive redaction; only values disappear, so a finding can
// still say "session cookie lacks Secure" without holding the session.
export function analyzeCookies(setCookieLines, { https = true } = {}) {
  const results = [];
  for (const line of Array.isArray(setCookieLines) ? setCookieLines : []) {
    const parts = String(line).split(";").map((part) => part.trim());
    const first = parts[0] || "";
    const equals = first.indexOf("=");
    if (equals < 1) continue;
    const name = first.slice(0, equals);
    const lowerAttributes = parts.slice(1).map((part) => part.toLowerCase());
    const sameSiteAttr = lowerAttributes.find((part) => part.startsWith("samesite="));
    const domainAttr = lowerAttributes.find((part) => part.startsWith("domain="));
    const pathAttr = lowerAttributes.find((part) => part.startsWith("path="));
    const cookie = {
      name,
      secure: lowerAttributes.includes("secure"),
      httpOnly: lowerAttributes.includes("httponly"),
      sameSite: sameSiteAttr ? sameSiteAttr.slice("samesite=".length) : null,
      domain: domainAttr ? domainAttr.slice("domain=".length) : null,
      path: pathAttr ? pathAttr.slice("path=".length) : null,
      partition: lowerAttributes.includes("partitioned"),
    };
    cookie.notes = [];
    if (!cookie.secure && https) cookie.notes.push("no Secure attribute on an HTTPS origin");
    if (!cookie.httpOnly) cookie.notes.push("readable from JavaScript (no HttpOnly)");
    if (cookie.sameSite === null) cookie.notes.push("no SameSite attribute");
    if (cookie.domain && !cookie.domain.startsWith(".")) cookie.notes.push(`explicit Domain=${cookie.domain} widens scope to every subdomain`);
    if (name.startsWith("__Host-")) {
      if (!cookie.secure) cookie.notes.push("__Host- prefix without Secure");
      if (cookie.domain) cookie.notes.push("__Host- prefix with Domain (browsers reject it)");
      if (cookie.path !== "/") cookie.notes.push("__Host- prefix without Path=/");
    }
    if (name.startsWith("__Secure-") && !cookie.secure) cookie.notes.push("__Secure- prefix without Secure");
    results.push(cookie);
  }
  return results;
}

function headerLookup(headers, name) {
  const wanted = name.toLowerCase();
  const values = [];
  for (const line of Array.isArray(headers) ? headers : []) {
    const colon = line.indexOf(":");
    if (colon < 1) continue;
    if (line.slice(0, colon).trim().toLowerCase() === wanted) values.push(line.slice(colon + 1).trim());
  }
  return values;
}

export function getHeader(headers, name) {
  const values = headerLookup(headers, name);
  return values.length > 0 ? values.join(", ") : null;
}

// A header audit is a list of observations, never a list of findings. Each entry says
// what was observed and what would make it matter.
export function analyzeHeaders(headers, { url = "", https = true } = {}) {
  const checks = [];
  const add = (id, state, detail) => checks.push({ id, state, detail });
  const hsts = getHeader(headers, "strict-transport-security");
  if (https) {
    if (!hsts) add("hsts", "missing", "no Strict-Transport-Security on the HTTPS response");
    else {
      const maxAge = Number((/max-age=([0-9]+)/i.exec(hsts) || [])[1] || 0);
      add("hsts", maxAge > 0 ? "present" : "weak", `Strict-Transport-Security: ${hsts}`);
    }
  }
  const csp = getHeader(headers, "content-security-policy");
  if (!csp) add("csp", "missing", "no Content-Security-Policy response header");
  else {
    const lower = csp.toLowerCase();
    const weak = [];
    if (lower.includes("unsafe-inline")) weak.push("unsafe-inline");
    if (lower.includes("unsafe-eval")) weak.push("unsafe-eval");
    if (lower.includes("*")) weak.push("wildcard source");
    add("csp", weak.length > 0 ? "weak" : "present", `Content-Security-Policy present${weak.length ? ` with ${weak.join(", ")}` : ""}`);
    if (!lower.includes("frame-ancestors")) add("csp-frame-ancestors", "missing", "CSP has no frame-ancestors directive");
  }
  const xfo = getHeader(headers, "x-frame-options");
  const cspFrames = csp ? csp.toLowerCase().includes("frame-ancestors") : false;
  if (!xfo && !cspFrames) add("framing", "missing", "neither X-Frame-Options nor CSP frame-ancestors is set");
  else add("framing", "present", xfo ? `X-Frame-Options: ${xfo}` : "CSP frame-ancestors present");
  const nosniff = getHeader(headers, "x-content-type-options");
  add("nosniff", nosniff && nosniff.toLowerCase().includes("nosniff") ? "present" : "missing", "X-Content-Type-Options: nosniff");
  const referrer = getHeader(headers, "referrer-policy");
  add("referrer-policy", referrer ? "present" : "missing", referrer ? `Referrer-Policy: ${referrer}` : "no Referrer-Policy header");
  const permissions = getHeader(headers, "permissions-policy");
  add("permissions-policy", permissions ? "present" : "missing", permissions ? `Permissions-Policy: ${permissions}` : "no Permissions-Policy header");
  const coop = getHeader(headers, "cross-origin-opener-policy");
  add("coop", coop ? "present" : "missing", coop ? `Cross-Origin-Opener-Policy: ${coop}` : "no Cross-Origin-Opener-Policy header");
  const corp = getHeader(headers, "cross-origin-resource-policy");
  add("corp", corp ? "present" : "missing", corp ? `Cross-Origin-Resource-Policy: ${corp}` : "no Cross-Origin-Resource-Policy header");
  const cacheControl = getHeader(headers, "cache-control");
  add("cache-control", cacheControl ? "present" : "missing", cacheControl ? `Cache-Control: ${cacheControl}` : "no Cache-Control header (heuristic caching may apply)");
  const vary = getHeader(headers, "vary");
  add("vary", vary ? "present" : "missing", vary ? `Vary: ${vary}` : "no Vary header");
  for (const name of ["server", "x-powered-by", "x-aspnet-version", "x-generator"]) {
    const value = getHeader(headers, name);
    if (value) add(`disclosure-${name}`, "present", `${name}: ${value}`);
  }
  const poweredBy = getHeader(headers, "x-powered-by");
  if (poweredBy) add("version-disclosure", "present", `framework version disclosed via X-Powered-By: ${poweredBy}`);
  const setCookies = headerLookup(headers, "set-cookie");
  const cookies = analyzeCookies(setCookies, { https });
  return { url, checks, cookies };
}

export function corsAssessment({ requestOrigin, headers, https = true }) {
  const allowOrigin = getHeader(headers, "access-control-allow-origin");
  const allowCredentials = (getHeader(headers, "access-control-allow-credentials") || "").toLowerCase() === "true";
  const allowMethods = getHeader(headers, "access-control-allow-methods");
  const allowHeaders = getHeader(headers, "access-control-allow-headers");
  const vary = getHeader(headers, "vary");
  let verdict = "none";
  if (allowOrigin === "*") verdict = allowCredentials ? "wildcard-with-credentials" : "wildcard";
  else if (allowOrigin && requestOrigin && allowOrigin === requestOrigin) verdict = "reflected";
  else if (allowOrigin) verdict = "fixed";
  const notes = [];
  if (verdict === "reflected") notes.push("the response reflects the request Origin verbatim");
  if (verdict === "reflected" && allowCredentials) notes.push("reflected Origin plus credentials lets the requesting origin read authenticated responses");
  if (verdict === "wildcard") notes.push("any origin may read the response, but cookies are not sent");
  if (verdict === "reflected" && vary && vary.toLowerCase().includes("origin")) notes.push("Vary: Origin is set, so a shared cache is less likely to mix responses");
  if (verdict === "reflected" && (!vary || !vary.toLowerCase().includes("origin"))) notes.push("no Vary: Origin on a reflected origin, so a shared cache may serve one origin's response to another");
  return { requestOrigin, allowOrigin, allowCredentials, allowMethods, allowHeaders, vary, verdict, notes };
}

export function cacheAssessment(headers) {
  const cacheControl = getHeader(headers, "cache-control") || "";
  const lower = cacheControl.toLowerCase();
  const hints = {};
  for (const name of ["age", "expires", "x-cache", "cf-cache-status", "x-served-by", "x-varnish", "x-cache-hits", "cdn-cache", "x-fastly-request-id", "via"]) {
    const value = getHeader(headers, name);
    if (value) hints[name] = value;
  }
  return {
    cacheControl,
    vary: getHeader(headers, "vary"),
    public: /\bpublic\b/.test(lower),
    private: /\bprivate\b/.test(lower),
    noStore: /\bno-store\b/.test(lower),
    noCache: /\bno-cache\b/.test(lower),
    maxAge: Number((/max-age=([0-9]+)/.exec(lower) || [])[1] || 0),
    sMaxAge: Number((/s-maxage=([0-9]+)/.exec(lower) || [])[1] || 0),
    cdnHints: hints,
  };
}

export function fingerprintBody(body) {
  const text = String(body || "");
  const markers = [
    ["wordpress", /\/wp-content\/|wp-json/i],
    ["drupal", /drupal-settings-json|sites\/default\/files/i],
    ["shopify", /cdn\.shopify\.com|shopify-section/i],
    ["next.js", /__NEXT_DATA__|\/_next\//i],
    ["nuxt", /__NUXT__|\/_nuxt\//i],
    ["angular", /ng-version=|ng-app=/i],
    ["react", /data-reactroot|__REACT_DEVTOOLS/i],
    ["vue", /data-v-[0-9a-f]{8}|__VUE__/i],
    ["laravel", /laravel_session|csrf-token" content=/i],
    ["django", /csrfmiddlewaretoken/i],
    ["rails", /csrf-param|authenticity_token/i],
    ["aspnet", /__VIEWSTATE|ASP\.NET_SessionId/i],
    ["joomla", /\/media\/system\/js\//i],
    ["cloudflare", /cf-ray|__cf_bm|cdn-cgi\/challenge/i],
    ["svelte", /svelte-[0-9a-z]{6}/i],
    ["webpack", /webpackJsonp|__webpack_require__/i],
  ];
  const found = [];
  for (const [tech, pattern] of markers) {
    const match = pattern.exec(text);
    if (match) found.push({ tech, evidence: match[0].slice(0, 80) });
  }
  return found;
}

// Scope is a list of host rules. A leading dot in `host` matches any subdomain.
export function matchesScope(urlString, scope) {
  let parsed;
  try {
    parsed = new URL(urlString);
  } catch {
    return false;
  }
  const host = parsed.hostname.toLowerCase();
  const protocol = parsed.protocol === "https:" ? "https" : parsed.protocol === "http:" ? "http" : null;
  if (!protocol) return false;
  const outOfScope = Array.isArray(scope?.out_of_scope) ? scope.out_of_scope : [];
  if (outOfScope.some((entry) => hostRuleMatches(entry, host))) return false;
  const rules = Array.isArray(scope?.in_scope) ? scope.in_scope : null;
  if (!rules) return false;
  return rules.some((rule) => {
    if (!hostRuleMatches(rule.host, host)) return false;
    const prefix = typeof rule.path_prefix === "string" && rule.path_prefix.length > 0 ? rule.path_prefix : "/";
    if (!parsed.pathname.startsWith(prefix)) return false;
    if (Array.isArray(rule.schemes) && !rule.schemes.includes(protocol)) return false;
    return true;
  });
}

function hostRuleMatches(rule, host) {
  if (typeof rule !== "string") return false;
  const normalized = rule.trim().toLowerCase();
  if (normalized.startsWith(".")) return host === normalized.slice(1) || host.endsWith(normalized);
  if (normalized.includes("*")) {
    const suffix = normalized.slice(normalized.indexOf("*"));
    return host.endsWith(suffix.slice(1));
  }
  return host === normalized;
}

export function scopeAllowsMethod(scope, method) {
  const rules = Array.isArray(scope?.in_scope) ? scope.in_scope : [];
  const allowed = new Set();
  for (const rule of rules) {
    for (const entry of Array.isArray(rule.methods) ? rule.methods : []) allowed.add(String(entry).toUpperCase());
  }
  if (allowed.size === 0) return ["GET", "HEAD", "OPTIONS"].includes(String(method).toUpperCase());
  return allowed.has(String(method).toUpperCase());
}

// A capture is the only evidence the validators accept, so its shape is fixed here.
export function captureSkeleton({ label, request, response, redirects = [], timings = {}, notes = [] }) {
  return {
    capture_version: 1,
    label,
    observed_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    request,
    response,
    redirects,
    timings,
    notes,
  };
}

export function captureObservation(capture, artifactPath) {
  const request = { method: capture.request.method, url: capture.request.url };
  if (Array.isArray(capture.request.headers) && capture.request.headers.length > 0) request.headers = capture.request.headers;
  if (capture.request.body_excerpt) request.body_excerpt = capture.request.body_excerpt;
  const response = { status: capture.response.status };
  if (Array.isArray(capture.response.headers) && capture.response.headers.length > 0) response.headers = capture.response.headers;
  if (capture.response.body_excerpt) response.body_excerpt = capture.response.body_excerpt;
  return {
    label: capture.label,
    artifact: artifactPath,
    observed_at: capture.observed_at,
    request,
    response,
  };
}
