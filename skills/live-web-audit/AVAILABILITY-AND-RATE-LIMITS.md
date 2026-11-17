# Availability and Rate-Limit Hunting

#### When to use this file

Reach for this file when a request does expensive work: search, exports, PDF/image rendering, password hashing, third-party calls, LLM calls, or anything that fans out. The goal is to describe a limit that is missing, not to exhaust a shared service.

## Core discipline (include in every hunter prompt for this domain)

```text
- Require input-to-cost, a missing effective bound, and an impact on someone other
  than the requester. Your own slow request is a performance note.
- Find the earliest limit that applies before declaring one missing: body size, query
  length, page size, per-identity quota, edge rate limit, concurrency, timeout.
- Never validate availability with load. Use a single request with a larger input, a
  second concurrent request, and measured time, then stop.
- Prefer a request that is cheap for you and expensive for the server; say why.
- Record the response time and the size you sent, in the capture or in the check note.
```

## Cost classes (subagent_type: `general`)

**Pre-authentication work**

Password hashing, key lookups, PDF rendering, and third-party calls reachable anonymously. Compare a request that fails authentication early with one that forces the expensive work, and state which one an anonymous client can repeat.

**Amplification by input shape**

A short input that expands: nested JSON, a zip, an image with huge dimensions, a search with many terms, a GraphQL alias batch. Send one expanded input and compare the response time or the size of the work with the baseline; that is enough.

**Pagination and export size**

An export that takes a `limit` far above the UI's value, a page size of 10,000, or an unbounded date range. Capture the accepted response (or the timeout) and name what the server did.

**Third-party and paid calls**

A signup, invite, or profile field that triggers an email, an SMS, a geocode, or a model call. One request proves the trigger; the per-identity bound is the question. Do not repeat to find the quota.

## Limit classes (subagent_type: `general`)

**Rate limits and lockout**

One login attempt, one reset, one SMS: note the response, then state whether a limit was observable from the headers (`Retry-After`, `X-RateLimit-*`) or by a second attempt. Do not run a guessing loop.

**Quota scope**

A limit keyed on an attacker-controlled dimension (an IP header, a cookie, a path, a tenant field). Change one dimension and see whether the counted work resets. Capture both responses.

**Concurrency and race**

Two identical requests in parallel on a check-then-act endpoint (redeem, vote, transfer with a test identity). The evidence is two successes where one was expected. One pair, not a burst.

**Timeout and disconnect work**

A request the client aborts after the headers; whether the server keeps working needs an observable second effect (a log line, a delayed resource, a later response). Otherwise `needs_validation`.

## Universal moves

- Measure the baseline first; without it a slow response means nothing.
- Keep the input increase modest: doubling is enough to show a trend, and it is polite.
- Always check for an `Age`, `Retry-After`, or rate-limit header before claiming no limit.

## Validation rules (apply before reporting ANY finding here)

1. Cite the baseline and the expanded request, with the measured time or accepted size.
2. Name the earliest limit that exists and why it does not cover the path.
3. State the impact on another principal or on operator-owned cost, not on your own request.
4. Never run more than a handful of requests for this class; state the count.
5. If the deployed edge might bound the path, keep `needs_validation` with the header or quota an owner must check.
