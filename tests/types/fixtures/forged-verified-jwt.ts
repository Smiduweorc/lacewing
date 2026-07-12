/**
 * NEGATIVE FIXTURE - this file MUST NOT compile (LW-decode.1).
 *
 * `jwtVerify` is the only thing that can mint a `VerifiedJwt`. A caller cannot
 * hand-roll one out of a plain object and pass it into code that expects proof
 * of verification.
 */

import type { VerifiedJwt } from "../../../index.js";

// ERROR: the object literal has no `__brand`, so it is not a VerifiedJwt.
export const forged: VerifiedJwt = {
	header: { alg: "HS256" as never, typ: "at+jwt" },
	payload: {
		iss: "https://auth.example.com",
		aud: "https://api.example.com",
		exp: 1,
		iat: 0,
	},
};
