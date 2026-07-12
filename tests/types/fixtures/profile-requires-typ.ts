/**
 * NEGATIVE FIXTURE - this file MUST NOT compile (RFC 8725 §3.11/§3.12).
 *
 * `typ`, `issuer`, `audience`, `algorithms`, `keys` and `maxTokenAge` are
 * structurally mandatory on a profile. A profile that "forgot" its `typ` - the
 * thing that keeps token kinds mutually exclusive - must not typecheck.
 */

import { defineProfile, generateSecret } from "../../../index.js";

// ERROR: property "typ" is missing in the argument.
export const noTyp = defineProfile({
	issuer: "https://auth.example.com",
	audience: "https://api.example.com",
	algorithms: ["HS256"],
	keys: generateSecret("HS256"),
	maxTokenAge: "10m",
});
