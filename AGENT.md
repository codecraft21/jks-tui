# Agent guidance

- Read `README.md` for the current scope, run instructions, and development checks.
- Keep changes focused on the small TUI; introduce modules as responsibilities grow.
- Preserve terminal cleanup through `ratatui::run` and all documented quit shortcuts.
- Keep dependency features minimal; review the `jks` compatibility note in
  `Cargo.toml` before changing its features.
- For keystore work, use generated test fixtures and keep passwords, private keys,
  and real keystores out of logs and commits.
- After code or dependency changes, run the checks in the README's Development
  section. For TUI changes, also exercise rendering, input, and terminal restoration
  in an interactive terminal.
- Update `README.md` when user-visible behavior changes. Report what changed,
  which checks ran, and any unresolved failures.
