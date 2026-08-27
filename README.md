# dsh-approval-gate

Host-only DeepSeek Harness guard for dangerous bash, service, database, and
secret-file operations. A matching explicit approval is required before such
commands can run.

## Installation

```sh
dsh plugin --profile web add @goodandready-private/dsh-approval-gate
```

The package is published privately to GitHub Packages. Keep the guard enabled
in profiles that need command-safety protection. See `docs/testing/private-route.md` for the test matrix.
