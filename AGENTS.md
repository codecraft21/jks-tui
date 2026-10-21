# Agent guidance

- Read `README.md` for the current scope, run instructions, and development checks.
- Use the configured GitHub plugin to publish commits, create pull requests,
  check CI, and merge. Use local Git for inspection and checkout management;
  publishing must not require Git credentials in the workspace.
- Keep changes focused on the small TUI; introduce modules as responsibilities grow.
- Preserve terminal restoration on initialization failure, errors, and normal exit,
  along with all documented quit shortcuts.
- Keep dependencies and their features minimal. The JKS format is parsed in
  `src/keystore.rs`; its only cryptographic dependency is SHA-1 hashing.
- Keep the app self-contained: opening keystores must work without Java or
  `keytool` installed. Use those tools only to generate development fixtures.
- For keystore work, use generated test fixtures and keep passwords, private keys,
  and real keystores out of logs and commits.
- After code or dependency changes, run the checks in the README's Development
  section. For TUI changes, also exercise rendering, input, and terminal restoration
  in an interactive terminal.
- Update `README.md` when user-visible behavior changes. Report what changed,
  which checks ran, and any unresolved failures.
