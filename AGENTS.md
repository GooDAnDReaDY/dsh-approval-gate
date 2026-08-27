# Project instructions

- Project: `dsh-approval-gate`.
- Package route: private `@goodandready-private/dsh-approval-gate` in GitHub Packages.
- This is a host-only DSH plugin; the Cordis patch names the private package and the host export remains the stable plugin id `dsh-approval-gate`.
- OPT is not applicable; production installs the immutable package version into the DSH profile.
- Preserve the safety guard behavior and do not put credentials, machine paths, or local install paths in tracked files.
- Use only Git worktrees and `git-codex`; the permanent lanmode plugin and Hermes files are out of scope.

See `index.md` and `docs/`.
