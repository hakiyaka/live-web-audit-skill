# Authentication and Session Hunting

#### When to use this file

Reach for this file whenever the site has a login, a session cookie, a bearer token, a recovery flow, MFA, SSO/OIDC, API keys, or a "remember me" path. These are the boundaries where a client proves who it is; a defect here makes every other control irrelevant.

Pair it with [ACCESS-CONTROL.md](ACCESS-CONTROL.md) once identity is established, and with [CACHE-AND-PROXY.md](CACHE-AND-PROXY.md) when a cache sits between login and the account pages.

## Core discipline (include in every hunter prompt for this domain)

```text
- Log every request in the sequence with its own capture: pre-login, login POST,
  post-login, logout, post-logout. A session claim needs at least two of them.
- Never guess credentials. Use only the operator-supplied test identities, and never
  register an account unless the operator explicitly allowed it.
- Separate "the response differs" from "the account is compromised". An error message
  parity difference is an enumeration lead, not a takeover.
- Treat a token as a credential: redact it, name its scope and lifetime, and show the
  request that proves whether the server accepts it after it should be invalid.
- If a decisive step needs a second identity, a mail inbox, or the IdP, keep
  needs_validation and give the exact next probe or owner check.
```

## Login and session classes (subagent_type: `general`)

**Session fixation**

Capture the cookie value before login, log in with the test identity, capture again. The same value after a successful login means the server kept a client-chosen identifier. To prove exploitability you need the pre-login cookie to be settable by a third party; state how (URL parameter, a login page that echoes a cookie, a sibling subdomain) or mark `needs_validation`.

**Session invalidation on logout and privilege change**

Replay the post-login cookie after logout, after a password change, and after an email change. A still-valid cookie is a captured defect. Check the same for remember-me tokens, refresh tokens, and any `session` value in a URL.

**Login error parity and enumeration**

Compare responses for a known-good username with a wrong password, an unknown username, and a locked account. Status, body, and timing are three separate oracles. Enumeration alone is low; it becomes meaningful with a reset flow or an unthrottled login.

**Alternate login doors**

Enumerate what the site itself links: `/api/login`, `/mobile/login`, basic auth on a subpath, a magic-link endpoint, a debug impersonation parameter, an SSO callback that accepts an email. Test only doors the site advertises in markup or bundles.

**Remember-me and long-lived tokens**

Capture a remember-me cookie, then use it after logout and after a password change. Name the lifetime from the cookie or the token itself.

## Recovery and MFA classes (subagent_type: `general`)

**Password reset binding**

Request a reset for the test identity and read what comes back: token in the URL, one-time link, or a code. Check whether the response for an unknown address differs, whether the token appears in a `Referer`-leaking page, and whether the token survives a second request. Do not attempt to reset another principal's password.

**Reset token transport and reuse**

A token that appears in a `Location`, a `Referer`, or an analytics URL is leaked to third parties. A token reusable after a successful reset is a second defect. Capture each use.

**MFA and step-up bypass**

After a first factor, check whether the account pages answer before the second factor, and whether any alternate route (API, mobile, legacy path) skips it. Name the exact request that returns account data without the second factor.

**Enrollment without step-up**

Add a second factor, replace a factor, or create a recovery code and see whether the site required fresh authentication. Without a second identity this is usually a `needs_validation`.

## Token classes (subagent_type: `general`)

**JWT verification**

Decode the token (base64 of the middle segment) and record `alg`, `iss`, `aud`, `exp`, `kid`, and the claims that matter. Send it to a surface that should accept it a second time; try a token from another environment if the site exposes one. `alg: none` acceptance, missing `exp` enforcement, and `aud`/`iss` not checked are captured defects when a request proves them.

**Token in URL or storage**

Tokens in query strings leak through `Referer`, logs, and shared links; tokens in `localStorage` are readable by any script on the origin. Name the reader and the leak path before assigning impact.

**API keys and client credentials**

Classify a key found in a bundle: publishable keys are expected; a secret key that authorizes a captured request is a finding. Prove it by using it exactly once against the endpoint it names.

**OAuth and SSO callback binding**

For a site that acts as a relying party: capture the authorization request (state, nonce, PKCE, redirect_uri) and the callback. Look for a missing `state`, an unvalidated `redirect_uri`, a callback that logs the user into a session chosen by the attacker, or an account created by linking an unverified email. Do not complete a flow for another person's account.

## Universal moves

- Draw the identity graph: anonymous, test identity, role, tenant, device. For each edge, name the proof the site requires.
- Compare UI routes with API routes for every auth step; the API is usually the weaker door.
- Replay each credential in every place it is accepted: cookie, header, query, body.
- Keep the whole login sequence in one artifact per step so a verifier can replay it in order.

## Validation rules (apply before reporting ANY finding here)

1. Cite the before/after captures and the exact cookie or token, redacted.
2. Name which identity the captured request used, and prove the server saw that identity.
3. For fixation, naming, and reuse claims, show the second acceptance, not just the first.
4. For reset and MFA claims, state the flow steps and the exact request that skips a step.
5. Return `confirmed` only when a captured request shows the unauthorized state change or access; otherwise `needs_validation` with the identity or asset the run lacked.
