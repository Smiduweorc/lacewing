import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
	{
		ignores: [
			"dist/**",
			"docs/**",
			"node_modules/**",
			"examples/demo.ts"
		],
	},
	// Sensible baselines layered in beneath the project's own rules.
	js.configs.recommended,
	...tseslint.configs.recommended,
	{
		files: ["**/*.{js,mjs,cjs,ts,tsx}"],
		languageOptions: {
			parser: tseslint.parser,
		},
		rules: {
			// --- existing project formatting rules (kept) ---
			quotes: ["error", "double"],
			indent: ["error", "tab"],
			"no-tabs": "off",
			// --- added for a stricter, friendlier DX ---
			"no-console": "error",
			"@typescript-eslint/no-unused-vars": [
				"error",
				{
					argsIgnorePattern: "^_",
					varsIgnorePattern: "^_",
					caughtErrorsIgnorePattern: "^_",
				},
			],
			"@typescript-eslint/no-unused-expressions": [
				"error",
				{ allowTernary: true },
			],
			"@typescript-eslint/explicit-function-return-type": [
				"warn",
				{ allowExpressions: true },
			],
		},
	},
	{
		// The compliance gate and its runner are CLIs: printing to the console
		// is their whole job.
		files: ["tools/**/*.ts"],
		rules: {
			"no-console": "off",
		},
	}
);
