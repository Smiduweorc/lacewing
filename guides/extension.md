---
title: Building on Lacewing
---

# Building on Lacewing

**`lacewing/extension`, for packages that add a check on top of a Lacewing profile.**

## `lacewing/extension`

For packages that add a check on top of a Lacewing profile and must agree with
Lacewing about what a valid algorithm, duration or JWS segment is. It is
covered by semver like the root export, and it is read-only:

```ts
import { getAlgorithmProperties, isVerificationProfile, parseDuration, parseJsonObject, readHeaderValue } from "lacewing/extension";

getAlgorithmProperties("ES256"); // { name: "ES256", kty: "EC", crv: "P-256", minKeyBits: 256 }, frozen
getAlgorithmProperties("RS256", [LEGACY_RS256]); // legacy names answer only for a caller that passes them
parseDuration("15m");            // 900, as DurationSeconds
parseJsonObject(text, "header"); // a plain object, or JWT_INVALID; a member named twice, or __proto__/constructor/prototype, is refused
readHeaderValue(request, "dpop", "verifyProof"); // same source rules as parseBearer
isVerificationProfile(profile);  // true only for a profile defineProfile built
```

Descriptors come back frozen, so nothing that imports them can lower a
key-size floor for the rest of the process, and there is no registry to add
to: what one package opts into, by passing a `legacy/` descriptor, never
changes what another sees. Header validation is not exported: it
refuses an embedded `jwk`, which is right for a token and wrong for a format
that carries its own key, so each format owns its own header rules.
