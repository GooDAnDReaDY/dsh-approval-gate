# Test matrix

## Worktree
- Run `npm install --no-package-lock --ignore-scripts` and `npm test`.
- Cover parser classification (deny / ask / pass), nested substitutions, here-doc expansion, redirects, protected writes and non-string tool input.
- Verify protected-file reads are distinguished from writes and shell-expanded Authorization headers request approval.
- Confirm the monotonic guard only denies recognized dangerous actions; uncertain syntax uses `tools/pre-execute` ask.
- Run `npm pack --dry-run --json` and verify the explicit package allowlist and per-file size cap.

## Isolated DSH test profile
- Build the exact candidate tarball from the issue worktree and install it temporarily in the isolated MiniPC profile.
- Confirm the host bundle loads, ask and deny behavior work, and `dsh-lanmode` remains installed.
- Remove only the candidate plugin and tarball created for this test.

## Production candidate
- No production install, restart or profile edit is part of ordinary issue work.
- A later approved deployment uses the exact immutable package version and records health/smoke results.
