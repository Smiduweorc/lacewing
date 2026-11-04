/**
 * Provenance that cannot be forged or copied.
 *
 * A key, profile or key source is only trustworthy if Lacewing built it: an
 * object literal that merely has the right shape (`{ __brand: "LacewingKey",
 * key: weakBytes }`, or `{ ...profile, maxTokenAge: tenYears }`) skips every
 * check its factory makes. Each kind gets its own class with a private field;
 * `#minted in value` is true only for instances that class constructed, a
 * spread copy does not carry the field, and no state is kept anywhere.
 *
 * Two installed copies of Lacewing mint different classes, so a key from one
 * is refused by the other, the same as a legacy descriptor.
 */

export interface MintedKind<T extends object> {
	/** Freeze `fields` into an instance only this kind recognises. */
	mint(fields: T): T;
	/** Whether `value` was minted by this kind. */
	is(value: unknown): value is T;
}

export function mintedKind<T extends object>(): MintedKind<T> {
	class Minted {
		readonly #minted = true;

		constructor(fields: T) {
			Object.assign(this, fields);
			Object.freeze(this);
		}

		static is(value: unknown): boolean {
			return typeof value === "object" && value !== null && #minted in value;
		}
	}
	return {
		// The instance carries exactly T's own properties plus the private
		// field, which is invisible to the type system.
		mint: (fields) => new Minted(fields) as unknown as T,
		is: (value): value is T => Minted.is(value),
	};
}
