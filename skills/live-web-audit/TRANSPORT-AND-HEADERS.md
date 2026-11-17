# Transport and Header Hunting

#### When to use this file

Reach for this file for every live target: scheme and HSTS, TLS, cookie attributes, security headers, framing and MIME policy, and version disclosure. It covers the layer the browser and the edge enforce before the application sees the request.

Use it with [AUTH-AND-SESSION.md](AUTH-AND-SESSION.md) when a cookie carries identity, and with [CACHE-AND-PROXY.md](CACHE-AND-PROXY.md) when an edge sits in front of the origin.

## Core discipline (include in every hunter prompt for this domain)

```text
- A header is evidence about one response, not about the site. Compare HTML, API,
  asset, error, and redirect responses separately, and say which one you captured.
- Name the reader and the effect before calling anything a finding: a missing Secure
  needs plaintext reachability, a missing frame-ancestors needs a frameable
  state-changing action, a missing nosniff needs a resource the browser sniffs wrongly.
- Separate edge-owned from application-owned controls. A managed CDN may set HSTS for
  every host it fronts, or none; the capture shows what the client actually got.
- A version string is a disclosure. It becomes a finding only when the disclosed
  component is the one serving the captured surface and an advisory applies to it.
```

## Scheme and transport classes (subagent_type: `general`)

**HSTS and scheme downgrade**

Fetch `http://` and the `https://` origin, capture both. Confirm the redirect target, whether `Strict-Transport-Security` appears on the HTTPS response, its `max-age`, `includeSubDomains`, and `preload`. A missing HSTS alone is hardening; a plaintext session cookie or a login form that posts over `http://` is a defect.

**TLS configuration and certificate scope**

Use `harness.mjs tls`. Report protocol, cipher, issuer, validity window, SAN coverage of the hosts you actually use, and a chain that fails without `rejectUnauthorized: false`. A certificate that does not cover a host the application links to, or a validity window that has expired, is a captured fact. Cipher-suite preferences and downgrade attacks need a client you control; keep them `needs_validation`.

**Mixed content and absolute URLs**

Look for `http://` asset, form-action, or API URLs inside an HTTPS page. A browser blocks some and auto-upgrades others; state which, and whether the served page is the one users get.

## Cookie transport classes (subagent_type: `general`)

**Cookie attributes and scope**

Use `harness.mjs cookies`. Record name, `Secure`, `HttpOnly`, `SameSite`, `Domain`, `Path`, and prefix (`__Host-`, `__Secure-`). Then name the reader: a non-HttpOnly session cookie needs a same-origin script-injection or a third-party script to read it; a cookie without `Secure` needs a plaintext request that carries it; a `Domain` shared with a less-trusted subdomain needs that subdomain to be an attacker position.

**Cookie conflicts and duplicate names**

Capture a response that sets two cookies of the same name with different paths or domains, or a request that sends two values. A server that picks the first, last, or one by path can be driven by whichever copy an attacker can write.

**Session cookie on a shared parent domain**

When a session cookie is scoped to a registrable domain, list the sibling hosts that receive it and whether any is out of scope or more weakly controlled. That list is the concrete attacker position.

## Header and framing classes (subagent_type: `general`)

**Content Security Policy**

Capture the policy verbatim. Name the directives that matter for the sinks you found: `script-src` with `unsafe-inline` or a wildcard, missing `object-src`, missing `frame-ancestors`, `base-uri` unset. A weak CSP is only a finding when a reachable injection exists; otherwise it is the reason a weaker injection escalates.

**Framing and clickjacking**

Find a state-changing action reachable with one click. Then check `X-Frame-Options` and `frame-ancestors` on that response, and whether the page still renders inside a frame. Missing framing on a page with no state change is hardening.

**MIME sniffing and download content**

For a user-supplied file served from the application origin, capture `Content-Type`, `X-Content-Type-Options`, and `Content-Disposition`. A stored HTML or SVG served inline from the app origin is the classic path to stored script execution; state which of those controls is absent.

**Referrer and cross-origin policy**

`Referrer-Policy` and `Cross-Origin-Opener-Policy` change what a cross-site attacker can observe. Treat them as amplifiers of a specific leak, with the leak named.

**Server and version disclosure**

Capture `Server`, `X-Powered-By`, generator markup, and framework cookies. Keep the raw values in the evidence; treat severity as informational unless a known advisory matches the exact component and version and the component serves the captured surface.

## Universal moves

- Capture the same URL as HTML, as an API response, and as an error, and compare the header sets.
- Compare a first request and a second request: some edges set headers only on cache misses.
- Compare anonymous and authenticated responses for the same page; some sites degrade headers when a session exists.
- Keep exact header text in the evidence; never paraphrase a policy.

## Validation rules (apply before reporting ANY finding here)

1. Cite the capture, the header set, and the surface; say whether the edge or the application owns the control.
2. For a cookie claim, name the reader and the request that would carry the value.
3. For a TLS claim, state the host you connected to and whether the chain validated without `rejectUnauthorized: false`.
4. For a disclosure claim, name the component and how it is reachable; a banner alone is informational.
5. Return `confirmed` only when a captured effect accompanies the configuration; otherwise use `needs_validation` with the exact next probe.
