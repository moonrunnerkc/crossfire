import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  // fixtures/ holds deliberately insecure code and a hand-written fake agent,
  // neither of which is production surface.
  { ignores: ["dist/**", "node_modules/**", "fixtures/**", "runs/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      "no-empty": ["error", { allowEmptyCatch: false }],
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      "@typescript-eslint/consistent-type-imports": "error",
    },
  },
);
