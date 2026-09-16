# Plan: gate coverage block (#1 #7 #8 #9 #10 #11)

## Goal
Shell-aware fail-closed bash inspection, tests for every rule, file-write path coverage, ignore `openwiki/`, keep Gitea workflow files, generalize the denial string.

## Out of scope
Public npmjs. Package identity migration to `@goodandready/*`. New UI.

## Checks
- `node --test test/*.test.mjs`
- `npm pack --dry-run --json` allowlist
- Isolated DSH test profile install of the exact tarball after merge
