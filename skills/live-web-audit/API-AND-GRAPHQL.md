# API and GraphQL Hunting

#### When to use this file

Reach for this file when the site answers JSON, exposes documented or discovered routes (`/api`, `/v1`, `/v2`, `/graphql`), or has a mobile/partner surface that differs from the web one. APIs are where the UI's assumptions disappear and the server's real checks show.

Pair it with [ACCESS-CONTROL.md](ACCESS-CONTROL.md) for object scope and [INFO-DISCLOSURE-AND-CONFIG.md](INFO-DISCLOSURE-AND-CONFIG.md) for schema and error leakage.

## Core discipline (include in every hunter prompt for this domain)

```text
- Work from a real request the site makes: copy the shape, then change one field.
- A schema is not authorization: a documented field the UI omits may still be accepted.
- An API response is identity-bearing. State which session produced it and whether a
  cookie, bearer token, or key was required.
- Never enumerate an id space. Use ids the response itself exposes.
- Error bodies are evidence: capture them verbatim, clipped, because they tell a reader
  what the server expected.
```

## Route classes (subagent_type: `general`)

**Route and version parity**

Fetch the documented route, the same route with another version, the trailing-slash variant, and the `/internal` or `/partner` sibling. Capture the one that answers without the identity the others demanded, or with more fields.

**Undocumented endpoints from the client**

Take endpoint strings from the bundle, robots, and the OpenAPI document, then call the read endpoints the UI never uses. Capture each distinct response shape.

**Content-type handling**

Send the same JSON body as `application/json`, `text/plain`, a form encoding, and with a duplicate `Content-Type`. A parser that accepts a weaker type and skips validation on it is a captured bypass when a field changes the outcome.

**Method and override handling**

`X-HTTP-Method-Override`, `_method`, and `POST` on a `PUT` route. Capture the response that shows the override took effect.

## Field classes (subagent_type: `general`)

**Mass assignment**

Add fields the UI never sends to an update you are allowed to make: `role`, `tenant_id`, `owner_id`, `verified`, `plan`, `balance`. Read the object back and capture the reflected value. One accepted field is enough; do not escalate the change.

**Type coercion and duplicates**

Send a number as a string, a boolean as `0`/`1`, an array where an object is expected, and a duplicate key. A server that coerces differently than the client decides authorization or pricing on a different value than the one the client sees.

**Pagination, sort, and filter injection**

Sort and filter parameters that accept a field name: try a field the UI never offers, an unknown field, and a nested path. A change in ordering or an error naming the field is the evidence.

**Enumeration through errors**

A 404 for a missing id, a 403 for a foreign id, and a 400 for a malformed id separate existence from authorization. Capture the three; name the oracle.

## GraphQL classes (subagent_type: `general`)

**Introspection and schema**

Send the standard introspection query. A full schema for an anonymous caller is a disclosure; mark whether it is expected for this product.

**Alias batching and depth**

Repeat one field with aliases in a single request, and nest a recursive type. Capture the response; a server that answers without depth or cost limits is a limit observation until the cost is demonstrated.

**Field-level authorization**

Request a field the UI does not select on an object you own, then on an object you do not. A null field with an error is a check; a populated foreign field is the finding.

**Error verbosity**

GraphQL errors often carry resolver names, file paths, and query fragments. Capture one malformed query and keep the error text.

## Universal moves

- Keep the captured request as JSON or a raw body so a verifier can resend exactly.
- Compare an anonymous call, a test-identity call, and a call with the test identity's token in the wrong header.
- Prefer the endpoint that serves the most fields; authorization often lags there.

## Validation rules (apply before reporting ANY finding here)

1. Cite the copied request and the response that differs from the UI's expectation.
2. Name the identity, the object, and the field that proves a boundary moved.
3. For mass assignment, show the read-back value; for parser bypasses, show the field that took effect.
4. For enumeration, name the oracle and the status/body difference; treat it as low unless a recovery or throttle story follows.
5. Without a second object or identity, keep the access-control half as `needs_validation` with the exact next probe.
