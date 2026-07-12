/**
 * NEGATIVE FIXTURE - this file MUST NOT compile (RFC 8725 §3.1.2).
 *
 * A key is welded to exactly one algorithm at import time, and the algorithm
 * travels in the type. Swapping an ES256 key in where an HS256 key is expected
 * is a compile error, not a runtime surprise.
 */

import type { LacewingKey } from "../../../index.js";

declare const es256Key: LacewingKey<"ES256">;

// ERROR: LacewingKey<"ES256"> is not assignable to LacewingKey<"HS256">.
export const confused: LacewingKey<"HS256"> = es256Key;
