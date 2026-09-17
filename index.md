# dsh-approval-gate

Host-only DeepSeek Harness safety guard. Intercepts dangerous bash argv, uncertain shell syntax, and protected-file writes. Public package: @goodandready/dsh-approval-gate on npmjs.

- DEV: `/mnt/external/Project/DEV/dsh-approval-gate`
- OPT: not applicable; production installs the immutable GitHub Packages version in the DSH profile.
- Entry point: `lib/index.js`; inspector: `lib/inspect.js`; patch: `cordis.patch.yml`.
- Design: `docs/design/DESIGN.md`
- Tests: `npm install --no-package-lock --ignore-scripts`, then `npm test`.
- Deployment: `./deploy.sh <exact-version>` after publication.
- Test matrix: `docs/testing/private-route.md`.

Last verified: see the release issue after production install of the published version.
