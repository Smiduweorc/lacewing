---
title: Transport
---

# Transport

**Getting a token from the client to the server: cookies for browsers, bearer headers for services, and what both readers refuse.**

## Cookies and bearer headers

Do **not** put tokens in `localStorage` or `sessionStorage`: both are
readable by any script on the page, so one XSS means token theft. Lacewing
can't stop you doing that from your own frontend code. What it can do is make
the right way the easy one: an `HttpOnly` cookie (browsers) or an in-memory
bearer token (services):

```ts
import { setTokenCookie, readTokenCookie, parseBearer } from "lacewing";

setTokenCookie(response.headers, token); // always HttpOnly; Secure; SameSite, there is no option to drop them
const fromCookie = readTokenCookie(request);
const fromHeader = parseBearer(request); // strict RFC 6750; no query-string tokens, ever
```

The cookie defaults to the `__Host-` prefix and `SameSite=Lax`; `Strict` is
available, `None` throws.

Both readers refuse ambiguity rather than resolving it. `parseBearer` rejects
the `", "`-joined value `Headers` produces when a request carried two
`Authorization` headers, and `readTokenCookie` returns `undefined` when the
cookie name appears twice, the servers disagree about whether the first or the
last duplicate wins, and cookie shadowing is built on that disagreement.

Both readers take WHATWG `Headers` (or anything carrying them, like `Request`),
or the raw header string. Node-style frameworks - Express, Fastify, Koa - hand
you a plain object instead, so convert once at the edge; a shape the readers
don't accept throws rather than reading as "no token":

```ts
const headers = new Headers(req.headers as Record<string, string>);
const fromCookie = readTokenCookie(headers);

res.setHeader("Set-Cookie", buildTokenCookie(token)); // the response side is just a string
```
