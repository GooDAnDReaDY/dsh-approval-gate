# dsh-approval-gate

A host-only DeepSeek Harness safety guard that intercepts dangerous bash, service, database, and secret-file operations and requires explicit approval. Published privately as `@goodandready-private/dsh-approval-gate`.

- DEV: `/mnt/external/Project/DEV/dsh-approval-gate`
- OPT: not applicable; production installs the immutable GitHub Packages version in the DSH profile.
- Entry point: `lib/index.js`; bundle patch: `cordis.patch.yml`.
- Tests: `npm install --no-package-lock --ignore-scripts`, then `npm test`.
- Deployment: `./deploy.sh <exact-version>` after publication.
- Test matrix: `docs/testing/private-route.md`.

Last verified: 27.08.2026 on MiniAI and isolated MiniPC DSH test profile.
