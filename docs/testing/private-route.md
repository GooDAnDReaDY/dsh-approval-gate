# Test matrix

## Worktree
- `npm install --no-package-lock --ignore-scripts`
- `npm test`
- Covers package identity, argv inspection, prose false positives, unparseable fail-closed, file-write secret paths.

## Isolated DSH test profile
- Install the exact `.tgz` from merged `main` with the profile helper.
- Confirm the host bundle loads and `dsh-lanmode` remains installed.
- Cleanup the candidate plugin and tarball.

## Production candidate
- Same tarball, not a worktree `file:` path.
- Health of the web profile after install/restart.
- One safe command still runs; one dangerous command still denies.
