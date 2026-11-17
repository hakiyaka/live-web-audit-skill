# Cache and Proxy Hunting

#### When to use this file

Reach for this file when a CDN, reverse proxy, or framework cache answers before the application: `cf-cache-status`, `X-Cache`, `Age`, `Vary`, a CDN hostname, or a static-looking path. Cache bugs mix principals, which makes them high-value and easy to overclaim.

Use [CORS-AND-CROSS-ORIGIN.md](CORS-AND-CROSS-ORIGIN.md) when the cached response is read cross-origin, and [TRANSPORT-AND-HEADERS.md](TRANSPORT-AND-HEADERS.md) for what the edge adds.

## Core discipline (include in every hunter prompt for this domain)

```text
- A cache claim needs two sides: the input the origin used, and the key the edge used.
  Capture the same URL twice, and the variant request alongside its baseline.
- Prove the cached object was actually served: a cache-status header, a matching `Age`
  that advances, or a response that does not reach the origin.
- One unkeyed input per test. Changing three headers at once proves nothing.
- Never poison a shared object with content another user would see without the operator's
  consent; prefer a harmless marker, and say what remains in the cache.
```

## Key and variant classes (subagent_type: `general`)

**Cache key and unkeyed input**

Send a baseline request, then the same request with one extra input (`X-Forwarded-Host`, a query trick, a language header, a cookie). Capture both. If the body or a security-relevant header changes while `Vary` and the cache key do not mention that input, a shared cache can be made to serve the variant.

**Host and forwarded-header trust**

When the origin reflects `Host` or `X-Forwarded-Host` into links, redirects, script URLs, or a `Location`, capture the reflection. Whether that reaches a cache depends on the key; say which fact you captured.

**Query normalization and cache keys**

Try a trailing `?`, a duplicate parameter, a case variant, and a `;` parameter. A response that differs for the origin but shares the cache key is the interesting case.

**Vary correctness**

A response that varies by `Origin`, `Accept-Encoding`, or a cookie without a matching `Vary` can be served to the wrong requester. Capture the two variants and the missing directive.

## Private-content classes (subagent_type: `general`)

**Cache deception**

Fetch an authenticated page with a static suffix (`/account.css`, `/account;.png`, `/account/.jpg`). If the edge caches it and serves the authenticated body to an anonymous request, capture both. Without a second identity, use the test identity's own page and an anonymous replay; state the principal the cached body belongs to.

**Private response caching**

A page with account data carrying `Cache-Control: public`, or no cache header at all on a shared cache. Capture the headers and the body marker.

**Edge error pages**

A 404 or 500 rendered by the edge, cached, and served for other paths. Capture the edge response next to the application's own error page.

## Poisoning and normalization classes (subagent_type: `general`)

**Poisoning through an unkeyed header**

Choose a header the response reflects in a security-relevant place (a `Location`, a script `src`, a CSP report URI, a canonical link). Capture the variant, wait for a hit, then request the clean URL and see whether the variant is served. Keep the marker harmless.

**Edge versus origin normalization**

Compare `/a/../admin`, `/admin%2f`, `/admin;x`, and `/ADMIN` on both layers. A route the origin treats as one path and the edge as another is the mechanism for both deception and auth bypass; capture each interpretation.

**Request smuggling preconditions**

Look for a front end that rewrites `Transfer-Encoding`/`Content-Length`, HTTP/2 downgrade, or two length headers accepted. A smuggling claim without a second request observed as a victim is `needs_validation`.

## Universal moves

- Always capture `Age`, `Vary`, cache-control, and the edge-specific status header in the same capture as the body.
- Repeat the identical request twice; the second is the cache hit.
- Keep a baseline variant of every test URL so a verifier can see the difference.
- State the cache lifetime you measured, not the one the header claims.

## Validation rules (apply before reporting ANY finding here)

1. Cite the baseline, the variant, and the hit that served the wrong variant.
2. Name the input that was unkeyed and the header or body it changed.
3. For deception and private caching, name the principal the cached body belongs to and the anonymous request that received it.
4. For poisoning, say whether the marker was actually served from cache, and whether it persists.
5. Without a cache-status signal, keep it `needs_validation`; a missing `Vary` alone is hardening.
