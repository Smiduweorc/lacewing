/**
 * NEGATIVE FIXTURE - this file MUST NOT compile.
 *
 * How long a removed key stays trusted, how often a stranger can make you
 * fetch, and how long verification waits on the endpoint are the caller's
 * numbers. A remote JWKS that names none of them must not typecheck.
 */

import { createRemoteJWKSet } from "../../../index.js";

// ERROR: cacheTtlSeconds, cooldownSeconds and timeoutMs are missing.
export const guessed = createRemoteJWKSet("https://auth.example.com/jwks", {});
