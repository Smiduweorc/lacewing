/**
 * NEGATIVE FIXTURE - this file MUST NOT compile.
 *
 * A refresh-token profile without a revocation store is a long-lived token
 * nobody can kill. Leaving `revocation` out must not typecheck; opting out
 * takes `unsafeNoRevocation: true`.
 */

import { refreshTokenProfile, generateSecret } from "../../../index.js";

// ERROR: neither revocation nor unsafeNoRevocation is given.
export const unrevocable = refreshTokenProfile({
	issuer: "https://auth.example.com",
	audience: "https://auth.example.com/token",
	algorithms: ["HS256"],
	keys: generateSecret("HS256"),
});
