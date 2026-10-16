/**
 * NEGATIVE FIXTURE - this file MUST NOT compile.
 *
 * A claim refusal that does not say which claim it is about leaves
 * `error.claim` empty for the caller, so the claim codes require one.
 */

import { JWTError } from "../../../index.js";

// ERROR: MISSING_CLAIM needs { claim } in its options.
export const missing = new JWTError("MISSING_CLAIM", "Required claim is missing");
