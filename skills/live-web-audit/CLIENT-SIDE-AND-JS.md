# Client-Side and JavaScript Hunting

#### When to use this file

Reach for this file for single-page apps, bundles, client-side routing, browser storage, postMessage, service workers, and any page whose logic lives in JavaScript. These are the surfaces the server never sees: fragments, `window.name`, cross-window messages, and cached state.

## Core discipline (include in every hunter prompt for this domain)

```text
- A client-side candidate needs a controllable source and a sink that executes or
  discloses. Name both, and quote the lines from the bundle that connect them.
- The impact must reach another user's session, another origin, or persisted state.
  Self-XSS and reading your own storage are prerequisites, not findings.
- Framework escaping, CSP, SameSite, COOP/CORP, and the same-origin policy are real
  controls. Verify the one that would stop your path before claiming impact.
- Bundles are shipped source. Quote the exact string or function, with the asset URL,
  and keep the capture (or a hash of the asset) as evidence.
```

## Asset and inventory classes (subagent_type: `general`)

**Bundle and source-map disclosure**

List the scripts the page loads, and whether `.map` files answer on the same origin. A source map that returns the original sources is a disclosure; capture the map URL and the first source file. Note internal hostnames, environment names, feature flags, and admin routes found in the strings.

**Route inventory from the client**

Extract route tables and API paths from the bundle and compare them with what the markup links. Routes present in the client but not in navigation are the interesting set; fetch them without an identity and capture the response.

**Key classification**

Public keys (publishable, map tiles) are expected. A key that appears in a bundle is only a finding when a captured request proves it authorizes something. Use it once, against the endpoint it names.

## Sink classes (subagent_type: `general`)

**DOM XSS**

Sources: `location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage` data, storage. Sinks: `innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`, string-evaluating APIs, `eval`, `new Function`, `javascript:` URLs. Quote the assignment that connects them. If the sink is only reachable after a click or a route change, say so.

**Client route guards**

A route that renders an admin view from client state. Compare the data it fetches with the data the server would return for an anonymous caller: a guard that hides but does not enforce is confirmed when the underlying request answers without identity.

**Template and markup rendering**

Client templating with an unescaped binding (`v-html`, `dangerouslySetInnerHTML`, `{{{ }}}`, `[innerHTML]`). Name the value that reaches it.

## Messaging and storage classes (subagent_type: `general`)

**postMessage origin trust**

A handler that acts on `event.data` without an exact origin check, or with a prefix/substring check. Quote the handler. On the send side, sensitive data sent to `*` reaches any embedder; capture the message payload and the target origin.

**Browser storage and stale authorization**

Tokens, private responses, or role flags in `localStorage`, `sessionStorage`, `IndexedDB`, or Cache Storage that survive logout or account switch. Name the reader: any script on the origin, a less-trusted same-origin path, or a later account.

**Service worker scope and caching**

Capture the worker script URL, its `Service-Worker-Allowed` scope, and whether it caches authenticated responses with a key that omits the account. A worker that serves one account's cached page to another is confirmed only with the two responses captured.

**Cross-tab state**

`storage` events, `BroadcastChannel`, and shared workers that carry commands or identity between tabs. Confirm a stale tab can overwrite newer auth state; otherwise it is `needs_validation`.

## Universal moves

- Diff anonymous and authenticated bundle behaviour: the same JS often fetches different endpoints per role.
- Read the client's error handling of API responses; a 401 handled as "show cached page" is a storage story.
- Keep a copy of the exact asset response (or its hash) beside the quoted lines so a verifier can confirm the bundle is the one the site served.

## Validation rules (apply before reporting ANY finding here)

1. Cite the asset URL and the quoted line, plus the capture that proves the site served that asset.
2. Name the source, the sink, and the control that would stop the flow.
3. For storage and worker claims, name the reader and the account boundary crossed.
4. For postMessage and messaging claims, quote both sides: the sender's target origin and the receiver's check.
5. If execution or cross-account reach requires a browser this run did not drive, keep `needs_validation` with the exact page and step.
