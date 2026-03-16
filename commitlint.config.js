/** @type {import('@commitlint/types').UserConfig} */
export default {
  extends: ["@commitlint/config-conventional"],

  rules: {
    // Enforce conventional commit types relevant to this project
    "type-enum": [
      2,
      "always",
      [
        "feat",     // A new feature
        "fix",      // A bug fix
        "docs",     // Documentation only changes
        "style",    // Changes that do not affect meaning (formatting, whitespace)
        "refactor", // Code change that neither fixes a bug nor adds a feature
        "perf",     // A code change that improves performance
        "test",     // Adding or correcting tests
        "build",    // Changes to build system or external dependencies
        "ci",       // Changes to CI/CD configuration
        "chore",    // Maintenance tasks (dependency updates, tooling, etc.)
        "revert",   // Reverts a previous commit
        "security", // Security-related changes (hardening, patching vulnerabilities)
      ],
    ],

    // Subject line: sentence-case (first word capitalised, no trailing period)
    "subject-case": [2, "never", ["start-case", "pascal-case", "upper-case"]],
    "subject-full-stop": [2, "never", "."],

    // Keep the subject concise and descriptive
    "subject-min-length": [2, "always", 5],
    "subject-max-length": [2, "always", 72],

    // Body and footer line length (72 is standard for git readability in terminals)
    "body-max-line-length": [2, "always", 100],
    "footer-max-line-length": [2, "always", 100],
  },
};
