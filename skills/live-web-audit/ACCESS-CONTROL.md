# Access Control Hunting

#### When to use this file

Reach for this file for any surface that names an object, a role, or a tenant: order and invoice ids, profile paths, admin listings, exports, bulk actions, and API resources. Access control is the most productive live class because the difference between "allowed" and "not allowed" is one captured response.

Pair it with [AUTH-AND-SESSION.md](AUTH-AND-SESSION.md) for the identity and [API-AND-GRAPHQL.md](API-AND-GRAPHQL.md) for JSON routes.

## Core discipline (include in every hunter prompt for this domain)

```text
- A 403 is not proof of a check and a 200 is not proof of an authorization gap. Capturing
  an object that belongs to another principal, with its own identifiers visible, is proof.
- Always state the identity used and the owner of the object. Without a second identity,
  use objects the site exposes (ids in a listing, an author id in markup) and compare the
  response with the same request made anonymous.
- Test the same object through every door: UI route, API route, alternate method, batch
  endpoint, export, and any id in the body instead of the path.
- Never modify another principal's object more than the minimum needed. Prefer a read for
  the first proof; a write needs the operator's test data.
```

## Object-level classes (subagent_type: `general`)

**Object identifier substitution (BOLA/IDOR)**

Take an object id the test identity legitimately reads, then call the same endpoint with a differing id: the next integer, a uuid from another listing, an id found in public markup. Capture both responses. A body that contains the other object's data is confirmed. A redirect to login means the identity was absent, not that the check exists.

**Identifier shape and trust**

Ids that are sequential suggest enumeration; ids that are hashes do not. Test whether the server validates the format: a uuid endpoint fed an integer, a numeric endpoint fed a negative number, a path `..%2f` in a name field. A captured 500 with a stack trace is both an access-control lead and a disclosure.

**Ownership in the body**

Send the update the UI sends, plus an `owner_id`, `tenant_id`, `account_id`, or `user_id` field pointing elsewhere. If the response reflects the new owner or the object moves, capture it; mass assignment is in [API-AND-GRAPHQL.md](API-AND-GRAPHQL.md).

## Role and route classes (subagent_type: `general`)

**Role and permission parity**

For each privileged route the test identity can reach, try one more privileged route of the same family. Compare the anonymous response, the test-identity response, and any role marker in the body. The question is whether the server re-checks, not whether the UI hides it.

**Forced browsing to privileged routes**

Fetch `/admin`, `/admin/users`, `/internal`, `/api/admin/*` after observing them in markup, a bundle, robots, or a sitemap. A rendered admin page for an unprivileged identity is confirmed; a login redirect is not.

**Method and route parity**

Send the same resource with `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, and with trailing slash, `.json`, `;param`, and case variants. Capture the first method that answers with data the others refuse.

**API version parity**

`/v1` may enforce, `/v2` may not. Test the same object on both. Record the version in the evidence.

## Tenant and scope classes (subagent_type: `general`)

**Tenant selected by header, cookie, or subdomain**

When the site names a tenant in `X-Tenant`, a cookie, a path prefix, or a host, change it and keep the identity. A response with another tenant's data is confirmed; record which selector the server trusted.

**Bulk, export, and search scope**

List, export, report, and search endpoints often enforce less per-item authorization than single-object reads. Request a small export as the test identity and inspect whether rows outside its scope appear. Keep the export minimal.

**Counts and aggregates as an oracle**

A count, total, or autocomplete that includes foreign objects discloses existence even when the detail is protected. Capture the number with the expected value alongside.

**State-changing GET and CSRF-able actions**

An endpoint that mutates on `GET`, or a `POST` with no CSRF token and no `Origin` check, is an access-control story about the ambient credential. Capture the response to a foreign `Origin` and a foreign `Referer`.

## Universal moves

- Build the object table first: which ids exist, who owns each, which route reads it.
- Compare every pair of responses with a diff in mind: status, length, and the identifying fields only.
- Prefer the object the site itself exposes over a guessed id.
- Stop at the smallest foreign object; do not walk an id space.

## Validation rules (apply before reporting ANY finding here)

1. Cite the two captures: the identity's own object and the foreign object from the same route.
2. Name the identity used, the object's owner as the response itself reveals it, and the field that proves the mismatch.
3. For a write claim, show the resulting state, and state the minimum mutation made.
4. For a role claim, show the privileged content rendered for the lower role, not merely a 200.
5. Without a second identity or a foreign object, keep it `needs_validation` with the exact object class and identity needed.
