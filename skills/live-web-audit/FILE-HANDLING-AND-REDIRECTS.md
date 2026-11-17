# File Handling and Redirect Hunting

#### When to use this file

Reach for this file when a request names a file, an archive, a path, a download, an upload, or a URL the server will fetch or echo into a redirect: exports, avatars, invoices, thumbnails, imports, webhooks, image proxies, and login `next=` parameters.

## Core discipline (include in every hunter prompt for this domain)

```text
- Name the sink: a filesystem read, a filesystem write, a fetch, a redirect header, or a
  browser navigation. Each has a different proof.
- Encoded traversal is one family, not a spray. Pick one encoding that survives the
  server's normalization and show the file that came back.
- For an SSRF claim, the decisive fact is the fetch target and the response. Without an
  internal target or a collaborator endpoint, use timing and error differences and keep
  it needs_validation.
- For uploads, the decisive fact is where the file is served from, with which
  Content-Type, and whether the browser would execute it.
```

## Path classes (subagent_type: `general`)

**Path traversal in a parameter**

A `file=`, `path=`, `template=`, or `download=` parameter. Try `../` once, then one encoded variant (`..%2f`), then an absolute path. A returned file you can identify (a known static asset, `/etc/hostname` on a leaking error) proves the read. Stop there.

**Traversal in a stored filename**

An upload or export that reuses the client's filename. Send a name with a separator and capture the returned path or the download URL.

**Static serving and directory listing**

An asset directory that lists, or serves `..` in a normalized path. Capture the listing body; note whether it reveals backups or source files.

## Download and upload classes (subagent_type: `general`)

**Download content disposition**

For a user-supplied file served from the app origin, capture `Content-Type`, `Content-Disposition`, and `X-Content-Type-Options`. HTML, SVG, or XML served inline is the stored-XSS path; name the missing control.

**Upload type and re-serving**

Upload a harmless file with an unexpected extension, then fetch it back. A file stored under the app origin with an attacker-chosen type is confirmed when the response headers match the file's type and the body is yours.

**Archive and import handling**

An import that accepts a zip: a single entry with a traversal name is enough to see where it lands (an error naming the path, or a file that appears outside the expected directory). Do not overwrite existing content.

## Redirect classes (subagent_type: `general`)

**Open redirect**

A `next`, `return`, `redirect`, `continue`, or `url` parameter. Try an absolute foreign URL, a scheme-relative `//host`, and a `javascript:` value. An unfollowed `Location: https://probe.example` is the proof; capture it with `--max-redirects 0` or via the redirect command.

**Redirect chain composition**

A first-party redirect that forwards the destination into a second request (SSO, logout, magic link). The chain is where a foreign host can enter even when the first hop is validated.

**Header and scheme handling**

A `Location` built from a header or a parameter with a `data:` or `javascript:` scheme. Check whether the browser would follow it; keep the scheme in the evidence.

## Fetch classes (subagent_type: `general`)

**SSRF through a URL parameter**

Webhook, avatar-by-URL, PDF-from-URL, and image proxies. The decisive evidence is the server's request, not the response: use an operator-approved collaborator, or capture a response that unmistakably comes from an internal target (a metadata page, a router login, a health endpoint).

**Redirect following on the server side**

A fetch that follows redirects lets a public URL reach an internal one. Capture the two-step behaviour if you control the first hop; otherwise state it as the next probe.

**Scheme and port manipulation**

`file://`, `gopher://`, `dict://`, and unusual ports. One rejected and one accepted variant is the evidence; do not chain protocols.

## Universal moves

- Keep both the request and the served bytes (clipped) in the capture; filenames alone are not evidence.
- Compare a path you know exists with the traversal result: the difference in bytes is the proof.
- For uploads, fetch the file back through the site's own URL, not by guessing a storage host.

## Validation rules (apply before reporting ANY finding here)

1. Cite the request and the response that shows the file, the redirect, or the fetch result.
2. Name the sink and the normalization step that let the value through.
3. For traversal, show the identifiable file content; a status change alone is not enough.
4. For redirects, show the unfollowed `Location` and the scheme it carries.
5. For SSRF without a controlled collaborator, keep `needs_validation` with the internal target and port you propose to reach.
