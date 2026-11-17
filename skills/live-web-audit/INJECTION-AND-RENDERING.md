# Injection and Rendering Hunting

#### When to use this file

Reach for this file for any request value that comes back, is stored, or influences a query, a command, a path, or a rendered document: search boxes, profile fields, error messages, filters, sort keys, and import fields. This is where reflected, stored, and query-level injections live.

Use [CLIENT-SIDE-AND-JS.md](CLIENT-SIDE-AND-JS.md) for DOM sinks and [FILE-HANDLING-AND-REDIRECTS.md](FILE-HANDLING-AND-REDIRECTS.md) for path and archive handling.

## Core discipline (include in every hunter prompt for this domain)

```text
- Injection needs a sink and a context. Capture the exact byte that came back, in the
  exact place it appeared (HTML text, attribute, script, JSON, header, comment).
- A reflected value is not XSS. Name the escaping that is or is not applied, the
  element it lands in, and whether a browser would execute it. Without a browser check,
  a HTML-context reflection is a candidate; a quoted attribute or JSON string is weaker.
- Use one marker per context, not a payload list: a marker string, a quoted marker, a
  tag marker, and one arithmetic expression for template or SQL contexts.
- Stop at the differential. For SQL, prove the query changed; do not dump data.
```

## Reflection classes (subagent_type: `general`)

**Reflected XSS**

Send a unique marker in a parameter, a path segment, a header the page reflects, and an error trigger. Capture the response and locate the marker. Then classify: unescaped in the HTML body (`<` and `>` survive), in a quoted attribute (`"` survives), in a `<script>` block, in a JSON response consumed by the client, or in a `Location` header. Escaped everywhere means covered.

**Stored XSS**

Write the marker into a field the test identity owns (display name, bio, comment, address). Read it back on a page that renders it, and note whether the renderer escapes. If only the author sees it, say so; a self-XSS is a prerequisite, not a finding.

**Markup and sanitizer bypass**

When the site accepts limited HTML (Markdown, rich text), test whether the sanitizer keeps an event handler, a `javascript:` link, an SVG handler, or a `data:` URL. Capture the stored value and the rendered output.

**Header reflected into the body**

`Referer`, `X-Forwarded-Host`, `User-Agent`, and language headers are often echoed into HTML or links. Capture the response that shows the exact header value in a script or attribute context.

## Query and command classes (subagent_type: `general`)

**SQL injection**

Three probes, one injectable parameter: a single quote in a value and in a numeric field, a boolean pair (`id=1` vs `id=1' AND '1'='1`), and a comment terminator. A changed status, length, or error string is the differential. Time-based confirmation needs a measurable baseline and two repetitions; label it `needs_validation` if the timing is noisy.

**NoSQL and JSON operator injection**

Check whether a parameter accepts an object (`user[$ne]=x`, `{"$gt":""}` in a JSON body), and whether that changes the result set or bypasses a login check. One operator family is enough.

**Server-side template injection**

A name, subject, or filename rendered back by the server: `7*7`, `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`. A returned `49` proves evaluation. Name which syntax evaluated.

**Command and argument injection**

Export, convert, resize, ping, DNS-lookup, and PDF-generation parameters. Use a marker that changes the output (a filename suffix, an extra line, a delay) rather than a shell metacharacter chain. Stop at the marker.

**Header and CRLF injection**

A value in a redirect or cookie setter: an encoded separator (`%0d%0a`, `%E5%98%8A`) that lands in a response header. Capture the full header set, since many servers reject it silently.

## Log and downstream classes (subagent_type: `general`)

**Log injection and forged entries**

A marker with a newline that later appears in an operator view. Only capture the first render; do not chase the log pipeline.

**Stored text used as a URL, path, or expression**

A field that is safe in HTML but later used as an image URL, a redirect, a template, or a regex. Follow the marker into that second context, and say which one you reached.

## Universal moves

- Enumerate every place the value comes back: the page body, a JSON field, an email preview, a PDF export, an admin view.
- Compare the escaped and unescaped render of the same value in one capture pair.
- Prefer the target's own feature for the second context (avatar URL, redirect parameter, export filename).
- Keep the payload minimal and single-purpose so a verifier can tell which character mattered.

## Validation rules (apply before reporting ANY finding here)

1. Cite the injected request and the response containing the exact marker.
2. Name the context and the escaping: HTML body, attribute, script, JSON, header.
3. For XSS, state whether execution was proven or is inferred; inference without a browser check becomes `needs_validation`.
4. For SQL, template, and command injection, show the differential, not a data dump.
5. For stored values, show who can read them (author only, other users, anonymous) as the captures reveal it.
