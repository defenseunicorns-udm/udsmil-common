import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["dist/**", "node_modules/**", "coverage/**"],
  },
  // Type-checked rules for TypeScript source files
  ...tseslint.configs.recommendedTypeChecked,
  {
    files: ["**/*.ts"],
    languageOptions: {
      parserOptions: {
        project: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      "no-console": "error",
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
    },
  },
  // Disable type-checked rules for this config file itself (not in tsconfig)
  {
    files: ["eslint.config.mjs"],
    extends: [tseslint.configs.disableTypeChecked],
  },
  // @types/jest matcher helpers return `any`; unsafe-assignment is too noisy in tests
  {
    files: ["__tests__/**/*.ts"],
    rules: {
      "@typescript-eslint/no-unsafe-assignment": "off",
    },
  }
);
