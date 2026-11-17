# Information Disclosure and Configuration Hunting

#### When to use this file

Reach for this file for the files a site serves by accident: debug and status endpoints, version-control and backup files, source maps, error pages, default content, and the inventory that `robots.txt` and sitemaps hand you. This is the class with the highest volume of noise; the discipline is proving what a reader can do with what leaked.

## Core discipline (include in every hunter prompt for this domain)

```text
- A leaked artefact needs a reader and a use. A version string is informational; a
  reachable backup containing a session secret is high.
- Stay on paths the site itself reveals (robots, sitemaps, links, bundles, error pages).
  A short list the operator approved is allowed; a brute-force is not.
- Capture the response, not the filename. A 200 with a login page is not a hit.
- Prove the disclosure by fetching the next object that only the real file could name
  (a repository object, a source file line, a directory listing entry).
```

## Endpoint classes (subagent_type: `general`)

**Debug, actuator, and status endpoints**

`/debug`, `/actuator`, `/actuator/env`, `/actuator/heapdump`, `/server-status`, `/metrics`, `/health`, `/status`, `/phpinfo.php`, `/__debug__`. For each 200, capture the body excerpt and classify: environment variables, internal hosts, thread dumps, or nothing.

**Admin and internal routes**

Routes seen in robots, a sitemap, or a bundle: `/admin`, `/internal`, `/staging`, `/backoffice`, `/api/admin`. A rendered admin page for an anonymous caller is an access-control finding; a login page is inventory.

**Version-control and backup files**

`/.git/HEAD`, `/.git/config`, `/.svn/entries`, `/.hg/`, `/.env`, `/.DS_Store`, `/web.config`, `/.htaccess`, `/*.bak`, `/*.zip`, `/backup.sql`. Where a VCS directory answers, try one object path to show whether the repository content is readable; otherwise mark the lead and its blocker.

**Framework metadata**

Framework-specific defaults: `/_next/`, `/nuxt/`, `/wp-json/`, `/sites/default/`, `/actuator/mappings`, `/_ignition/`, `__debugbar`. Capture the response that names the framework and version.

## Content classes (subagent_type: `general`)

**Source maps and build metadata**

A `.map` served next to a bundle, a `//# sourceMappingURL` comment, a build id in a script tag. Capture the map's `sources` list (clipped) and any absolute paths it carries.

**Error pages and traces**

Force a 404, a 400, and where safe a 500 (a malformed parameter is usually enough). Capture stack traces, framework paths, SQL fragments, trace ids, and internal hostnames verbatim.

**Default and example content**

Default welcome pages, sample accounts, seeded demo pages, placeholder API keys, and commented-out markup. Capture the page and name what it exposes.

**Directory listing**

An asset or uploads directory that lists its contents. Capture the listing and note whether it reveals filenames an attacker could not otherwise know.

## Inventory classes (subagent_type: `general`)

**Robots and sitemap inventory**

Fetch `robots.txt` and every sitemap it names. Compare the entries with what the site links; the unlinked entries are the interesting set. Keep the file itself as a capture.

**Well-known surface**

`/.well-known/security.txt`, `/.well-known/openid-configuration`, `/.well-known/assetlinks.json`, `/.well-known/apple-app-site-association`. These are intended, but they name issuers, app ids, and endpoints; record what they reveal and whether it widens the attack surface.

**CORS and API documentation exposure**

`/swagger`, `/openapi.json`, `/api-docs`, `/graphql` with introspection. A full schema for an anonymous caller is an inventory win; treat it as a lead for the classes that use the schema.

## Universal moves

- Keep a short, fixed path list per run, derived from robots, sitemap, bundles, and one framework family; do not grow it while probing.
- Compare the 404 body across paths: a framework-specific 404 tells you which component answered.
- Use one capture per path so an inventory table can be built from captures alone.

## Validation rules (apply before reporting ANY finding here)

1. Cite the path, the status, and the body excerpt that carries the disclosure.
2. Name the component that served it (edge, framework, application) and the reader who can reach it.
3. For VCS and backup files, show the next object or a content line; a bare `/.git/HEAD` is a lead.
4. For schema and docs, say which class will use it; the disclosure alone is informational.
5. If a path is 200 but serves the SPA shell, say so and keep it out of the findings.
