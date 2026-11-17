# CORS and Cross-Origin Hunting

#### When to use this file

Reach for this file when the site answers `Access-Control-*` headers, accepts a foreign `Origin` on a WebSocket or SSE stream, embeds or is embedded in frames, or carries identity in a way another origin can read. This class turns "the header looks permissive" into "another origin read this response".

## Core discipline (include in every hunter prompt for this domain)

```text
- A CORS finding needs a response that carries data the requesting origin should not
  read, plus the exact headers that let it. Capture both the request with the foreign
  Origin and a baseline without it.
- Credentials matter: `*` with credentials never reaches a browser, so the interesting
  case is a reflected origin, or a fixed origin you can reach from an attacker page.
- Name the attacker origin with its authorization status: a subdomain, a third-party
  host, an `http://` page, a `null` origin sandbox.
- SameSite, COOP, and Vary change the answer. Capture them with the CORS headers.
```

## CORS classes (subagent_type: `general`)

**Reflected origin with credentials**

Send `Origin: https://probe.example`, capture the response, and compare with a request without `Origin`. `Access-Control-Allow-Origin` echoing the request origin with `Access-Control-Allow-Credentials: true` lets the probe origin read the body once it has a session. State whether the body carries identity-specific data.

**Wildcard with credentials**

`*` alone lets any origin read anonymous responses; combined with `Allow-Credentials: true` browsers reject the credential path, so the claim is usually about anonymous data (an API with no session, or a token in a query).

**Fixed allowlist overreach**

A fixed `Access-Control-Allow-Origin` for a host the attacker can control (a wildcard subdomain, a user-content domain, a staging host) is as good as a reflection. State how an attacker lands on that origin. Compare with `Access-Control-Allow-Origin: null` acceptance.

**Preflight behaviour**

`OPTIONS` with `Origin` and `Access-Control-Request-Method`. Capture `Allow-Methods`, `Allow-Headers`, `Max-Age`, and whether a method the UI never uses is allowed. A preflight that permits `DELETE` on a user resource is a lead, not a finding, until the DELETE works.

**Vary and cache interaction**

A reflected origin without `Vary: Origin` lets a shared cache serve one origin's response to another. Capture the two variants and the cache status if a cache is present.

## Cross-origin read classes (subagent_type: `general`)

**WebSocket and SSE origin**

Send a foreign `Origin` on the upgrade and keep a session cookie. A stream that accepts the connection and returns account data is captured. Note whether the server checks the origin or only the cookie.

**XS-Leaks and state oracles**

Frame, load, or navigate a cross-origin resource and observe load/error, size, timing, or redirect. Each oracle needs a concrete secret-bearing predicate and a captured difference between "true" and "false" states.

**Framing and postMessage exposure**

A page embeddable in a foreign frame, or a handler that replies with data to any parent. Capture the frameable response and the message exchange (or the handler code) and name the data disclosed.

**Window and navigation state**

A retained opener, a named window, or a navigation result that reveals protected state. Confirm with the exact browser behaviour you observed; otherwise `needs_validation`.

## Universal moves

- Always send the same request with and without `Origin`, and with a foreign `Origin`, and keep all three captures.
- Check whether the credentialed request is the one that matters: use the test identity's cookie only when the response body carries identity-specific data.
- Record `null` origin and `http://` origin variants; some implementations match loosely.

## Validation rules (apply before reporting ANY finding here)

1. Cite the foreign-origin capture, the baseline, and the identity (or its absence).
2. Quote the exact CORS headers and name the data that crosses.
3. For reflect-and-credentials claims, show that the endpoint serves identity-specific data to a browser request, not just to curl.
4. For WebSocket and messaging claims, capture the upgrade or the message exchange.
5. Without a browser to read the response, keep the impact as `needs_validation` with the exact origin, endpoint, and session needed.
