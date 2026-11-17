# Attack Classes

#### Attack classes — choose and split based on Phase 1

Select the classes the target actually exposes. Every class below is an observation exercise against a running site: you name a request, send it, capture the response, and decide whether a boundary moved. Reading a bundle or a header is allowed; reading the site's source repository is a bonus, not a requirement.

Use `confirmed` only when a captured response shows the boundary violation and its effect. Use `needs_validation` when the decisive step needs an identity, a second account, a cached layer, or an owner-only fact the run did not have.

> **Headers, TLS, and cookies** → [TRANSPORT-AND-HEADERS.md](TRANSPORT-AND-HEADERS.md)
>
> **Login, sessions, tokens, recovery** → [AUTH-AND-SESSION.md](AUTH-AND-SESSION.md)
>
> **Object-level and role-level authorization** → [ACCESS-CONTROL.md](ACCESS-CONTROL.md)
>
> **XSS, SQLi, template, command, and header injection** → [INJECTION-AND-RENDERING.md](INJECTION-AND-RENDERING.md)
>
> **SPAs, bundles, postMessage, storage, service workers** → [CLIENT-SIDE-AND-JS.md](CLIENT-SIDE-AND-JS.md)
>
> **CDN, cache keys, cache deception, poisoning** → [CACHE-AND-PROXY.md](CACHE-AND-PROXY.md)
>
> **CORS, WebSockets, cross-origin reads** → [CORS-AND-CROSS-ORIGIN.md](CORS-AND-CROSS-ORIGIN.md)
>
> **REST, GraphQL, versioning, mass assignment** → [API-AND-GRAPHQL.md](API-AND-GRAPHQL.md)
>
> **Uploads, traversal, redirects, SSRF targets** → [FILE-HANDLING-AND-REDIRECTS.md](FILE-HANDLING-AND-REDIRECTS.md)
>
> **Debug endpoints, backups, source maps, error pages** → [INFO-DISCLOSURE-AND-CONFIG.md](INFO-DISCLOSURE-AND-CONFIG.md)
>
> **Rate limits, quotas, expensive endpoints** → [AVAILABILITY-AND-RATE-LIMITS.md](AVAILABILITY-AND-RATE-LIMITS.md)

**Access control** (subagent_type: `general`)

A live access-control test needs two principals or one principal and one object it does not own. Without a second identity, you can still prove missing enforcement only when the target itself discloses the mismatch (a redirect to another tenant, a list that contains foreign ids, an admin action reachable anonymously).

- Swap an object identifier in a request that already worked for the test identity.
- Compare the UI's route with the API route it calls; send the API request the UI never sends.
- Try a state change with the method the UI does not use (PUT vs POST, PATCH vs POST), and with the id in the body instead of the path.
- Check list, export, bulk, and search endpoints, which often scope differently than single-object reads.
- Note whether a 403 is a real check or a redirect to login; a 302 to `/login` proves only that the session was absent.

**Authentication and session** (subagent_type: `general`)

- Compare the session cookie before and after login, logout, and a second login in the same jar.
- Replay a pre-login cookie on a post-login page; replay a post-logout cookie on a protected page.
- Check whether a password change, email change, or MFA step issues a new session value.
- Look for alternate login doors: `/api/login`, mobile endpoints, remember-me cookies, magic links, SSO callbacks, and any `?as_user=`, `?impersonate=`, or debug login parameter.
- One wrong credential is enough to see whether the response distinguishes existing from unknown accounts; stop there.

**Injection** (subagent_type: `general`)

- XSS: find a reflected value in the HTML body, attribute, JSON, or script context, then prove the exact context and the escaping that does or does not apply. A reflected value in a header, comment, or escaped node is not XSS.
- SQLi: a single quote, a numeric boundary `id=1` vs `id=1-0`, and a boolean pair are enough to see a behavioural difference; stop at the differential, do not dump data.
- Template and expression injection: arithmetic markers (`7*7`, `${7*7}`) in a name, search, or error path that is rendered by a server-side template.
- Command and file-path injection in export, thumbnail, PDF, and import parameters.
- Header injection: a CR/LF or encoded separator in a value that reaches `Location`, `Set-Cookie`, or a custom header.
- Log and downstream injection: a marker string that later shows up in an admin view, mail, or an index.

**Server-side request forgery and host trust** (subagent_type: `general`)

- Any URL, webhook, avatar, image proxy, PDF renderer, or import field is a fetch primitive. Use a target you control only if the operator approves an external interaction; otherwise use observable timing and error differences.
- Host and forwarded headers: send `X-Forwarded-Host`, `X-Forwarded-For`, `X-Original-URL`, and a foreign `Host` where scope allows. Look for the value in links, redirects, or cache keys.
- Absolute-URL parameters (`next=`, `return=`, `callback=`) are both an open-redirect and a fetch candidate.

**Cache and edge behaviour** (subagent_type: `general`)

- Send the same request twice and compare `Age`, `X-Cache`, `cf-cache-status`, and the body.
- Vary one unkeyed input at a time (query trick, `X-Forwarded-Host`, `Accept-Language`, cookie) and see whether the response changes while the cache key does not.
- Test whether a private page is cached when fetched with a static-looking suffix (`.css`, `.jpg`, `;.png`) or a path-normalization trick.
- Never assume the edge configuration; capture the evidence that a cached variant was actually served.

**Cross-origin and browser policy** (subagent_type: `general`)

- Send a foreign `Origin` and compare `Access-Control-Allow-Origin` and `-Credentials` against a baseline request without it.
- Confirm the value is reflected or fixed, and whether `Vary: Origin` exists.
- For a WebSocket or SSE endpoint, send a foreign `Origin` to the upgrade.
- `document.domain`, `window.name`, and `postMessage` behaviour require a browser check; otherwise `needs_validation`.

**Information disclosure** (subagent_type: `general`)

- Error pages with stack traces, framework versions, internal paths, SQL fragments, or trace ids.
- Robots, sitemaps, `/.well-known/`, source maps, and JS bundles naming internal hosts, feature flags, or test tenants.
- Verbose 401/403/500 bodies that separate "exists" from "forbidden".
- Version banners that map to a known advisory on a component the page actually uses.

**File handling and path traversal** (subagent_type: `general`)

- Uploaded file names, returned download paths, and archive entries.
- Encoded traversal (`..%2f`, `..%5c`, `....//`) only where a filename parameter exists; one probe per encoding family is enough.
- Redirect chains with a foreign destination, including scheme-relative and `javascript:`-style values.

**API and GraphQL abuse** (subagent_type: `general`)

- Version and route parity: `/v1` vs `/v2`, `/api` vs `/internal`, trailing slash and path-parameter variants.
- Mass assignment: add a field the UI never sends (`role`, `tenant`, `verified`, `owner_id`) to an update you are allowed to make, and see whether it takes.
- GraphQL: introspection query, `__typename`, alias-based batching, query depth, and whether errors reveal the schema.
- Verbose 400s that list accepted values.

**Business logic and race conditions** (subagent_type: `general`)

- Skip, repeat, or reorder steps in a multi-step flow; replay a completed step.
- Numeric manipulation: zero, negative, fractional, and over-boundary values in quantity, price, and offset fields.
- Two concurrent identical requests on a check-then-act endpoint (a single parallel pair is enough; no load).
- Expiry, timezone, and boundary-time behaviour on tokens and scheduling.

**Rate-limit and resource exhaustion** (subagent_type: `general`)

- Determine the earliest limit that applies, not whether a limit exists.
- A small number of concurrent expensive requests proves amplification only when the response time or the work per request is measurably asymmetric.
- Never validate availability by stress; stop after the smallest observed asymmetry.

**Transport and header configuration** (subagent_type: `general`)

- HSTS presence and `max-age`, TLS version and certificate chain, HTTP→HTTPS redirect, cookie flags, CSP, framing, MIME sniffing, referrer policy.
- A header alone is hardening until a reader or an effect is named: a missing `Secure` needs plaintext reachability, a missing `frame-ancestors` needs a state-changing frameable action.

**Client-side and JavaScript** (subagent_type: `general`)

- Bundle discovery, source maps, hardcoded endpoints, tenant ids, feature flags, and keys (public vs secret matters).
- DOM sinks fed by `location`, `window.name`, storage, or postMessage.
- Client-side route guards that hide but do not enforce server-side checks.

**AI and LLM endpoints** (subagent_type: `general`)

- Chat, completion, embedding, and tool endpoints with model-driven output or retrieval.
- Prompt injection into rendered output that reaches an executing sink, cross-conversation context bleed, and tool endpoints that act with a service identity.
- Model behaviour is non-deterministic: a claim needs two runs and an artifact each, or `needs_validation`.

**Wildcard** (subagent_type: `general`)

No category. Follow what looks half-finished, legacy, or inconsistent with the rest of the site:

- Which routes exist only in the bundle, in robots, in an old sitemap, or in a comment?
- Which endpoint accepts a parameter the UI never sends?
- What happens when a feature is disabled, mid-migration, or behind a flag you can flip in the URL?
- What changes between anonymous, test-identity, and mobile user agents?
- Which action affects another user, and was that containment captured?

**Obvious things** (subagent_type: `general`)

Check every item literally; this agent needs no creativity.

- `/.git/HEAD`, `/.env`, `/.svn/`, `/web.config`, `/backup.zip`, `/.DS_Store`
- `/admin`, `/debug`, `/actuator`, `/actuator/env`, `/server-status`, `/phpinfo.php`, `/metrics`, `/graphql`, `/swagger`, `/openapi.json`, `/api-docs`
- Directory listing on asset folders; index of `/uploads/`
- Default or example pages, demo accounts, seeded credentials
- `debug=1`, `test=1`, `X-Debug`, `X-Forwarded-For: 127.0.0.1`, `?env=dev`
- Cookies missing `Secure`, `HttpOnly`, `SameSite`, or with an over-broad `Domain`
- `Access-Control-Allow-Origin: *` with credentials, or a reflected origin
- Security headers absent on HTML but present on assets (or the reverse)
- `.map` files next to `.js`, comments containing TODOs, internal hostnames, or credentials
- Verbose error bodies, SQL errors, stack traces, timing gaps between 404 and 403
- HTTP methods that are allowed but undocumented (`OPTIONS`, `TRACE`, `PUT`)

For each hit, name the reader or the effect before calling it a finding. A `.git/HEAD` that returns a hash is a disclosure only when the repository content is reachable; capture the next object to prove it, or leave it `needs_validation`.
