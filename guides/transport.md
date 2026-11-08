---
title: Transport
---

# Transport

Don't put tokens in `localStorage` or `sessionStorage`. Any script on the
page can read both, so one XSS gives away every token. Use an `HttpOnly`
cookie in browsers and an in-memory bearer token between services:

```ts
import { setTokenCookie, readTokenCookie, parseBearer, clearTokenCookie } from "lacewing";

setTokenCookie(response.headers, token);
// __Host-token=...; Path=/; HttpOnly; Secure; SameSite=Lax

const fromCookie = readTokenCookie(request); // undefined if absent
const fromHeader = parseBearer(request);     // strict RFC 6750; throws BEARER_PARSE_FAILED if absent or malformed

clearTokenCookie(response.headers);          // logout
```

`HttpOnly`, `Secure` and `SameSite` are always set and there is no option to
drop them. `SameSite` defaults to `Lax`; `Strict` is available and `None`
throws. The default name uses the `__Host-` prefix, which binds the cookie to
the exact origin and forbids `Domain`. Query-string tokens are not supported.

Both readers refuse ambiguous input. `parseBearer` rejects the
`", "`-joined value `Headers` produces when a request carried two
`Authorization` headers. `readTokenCookie` returns `undefined` when the
cookie name appears twice, because servers disagree about whether the first
or the last duplicate wins, and cookie shadowing attacks rely on that.

## Node frameworks

Both readers take WHATWG `Headers`, anything carrying them (such as
`Request`), or the raw header string. Express, Fastify and Koa give you a
plain object, so convert once at the edge:

```ts
app.use((req, res, next) => {
  const headers = new Headers(req.headers as Record<string, string>);
  req.token = readTokenCookie(headers);
  next();
});
```

Passing the raw `req` throws a `TypeError` that names this fix, instead of
reading as "no token".

The response side is a string, so it works anywhere:

```ts
res.setHeader("Set-Cookie", buildTokenCookie(token));   // Express
reply.header("Set-Cookie", buildTokenCookie(token));    // Fastify
c.header("Set-Cookie", buildTokenCookie(token));        // Hono
```
