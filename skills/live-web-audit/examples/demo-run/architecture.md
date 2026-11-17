# Architecture summary

A three-page local demo shop served over plain HTTP on 127.0.0.1:8787.

- **Principals.** Anonymous visitor only. No login exists, so every access-control
  question is asked from the anonymous position.
- **Surfaces.** GET / (home, sets the sid cookie), GET /search?q= (server-rendered
  results), GET /admin (linked from the home page, renders user and refund counts).
- **Stack.** Node.js http module, no framework, no CDN, no cache layer.
- **Controls observed.** No security headers on any response; one cookie with no
  Secure, HttpOnly, or SameSite; /admin returns its body to an anonymous GET.
- **Identities available.** None beyond anonymous.
- **Companions selected.** INJECTION-AND-RENDERING.md (server-rendered q),
  ACCESS-CONTROL.md (unauthenticated admin route), TRANSPORT-AND-HEADERS.md (cookie
  and header posture).
- **Out of scope.** Nothing yet; the demo has three surfaces.
