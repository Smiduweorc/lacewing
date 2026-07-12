/**
 * NEGATIVE FIXTURE - this file MUST NOT compile (LW-decode.1).
 *
 * The core claim of the library: an unverified token can never be mistaken for
 * a verified one, and the compiler is what enforces it. No `@ts-expect-error`
 * here on purpose - `tests/types/negative.test.ts` runs `tsc` over this
 * directory and asserts the error is still raised. If this file ever starts
 * compiling, the brand has been broken and the gate goes red.
 */

import { unsafeDecode, type VerifiedJwt } from "../../../index.js";

const untrusted = unsafeDecode("a.b.c");

// ERROR: UntrustedJwt is not assignable to VerifiedJwt (the brands differ).
export const smuggled: VerifiedJwt = untrusted;
