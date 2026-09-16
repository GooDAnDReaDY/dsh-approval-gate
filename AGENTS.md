# Project instructions

This file complements the root DEV `AGENTS.md`. It records only facts specific to `dsh-approval-gate`.

## Product / Purpose

- Project: `dsh-approval-gate`
- DEV: `/mnt/external/Project/DEV/dsh-approval-gate`
- Package route: private `@goodandready-private/dsh-approval-gate` on GitHub Packages. Historical private identity is not renamed in ordinary tasks.
- Host-only DSH plugin. Cordis patch `id` is `dsh-approval-gate`. There is no client half.
- OPT is not applicable; production installs the immutable package version into the DSH profile.
- Design contract: `docs/design/DESIGN.md`

## Constraints (MUST NOT)

- Do not put credentials, machine paths, or local install paths in tracked files.
- Do not use `--force` on git, npm, or `dsh plugin`.
- Do not treat worktree paths as runtime dependencies.
- Do not delete or update `dsh-lanmode` while testing.
- Do not untrack `AGENTS.md`, `index.md`, or `deploy.sh` from Gitea; they are required project files. They are excluded from the npm allowlist.

## Tests

- `npm install --no-package-lock --ignore-scripts`
- `npm test`
- Matrix: `docs/testing/private-route.md`

## Deploy

- `./deploy.sh <exact-version>` after publication and owner approval.
