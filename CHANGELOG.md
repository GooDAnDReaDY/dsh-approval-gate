## 0.1.4

- The gate no longer raises an ask it knows cannot be answered. It reads the effective
  approval policy (`ctx.approval.config.policy`) and, when that policy is in
  `unattendedPolicies` (default `["never"]`, i.e. the full-access preset), an allowed command
  proceeds instead of dying as a rejection nobody could consent to. On 20.09.2026 exactly that
  turned every agreed write in such a session into `the user rejected tool`.
- Denials never depend on the policy: dangerous shell commands and writes to secret files are
  still blocked unconditionally, and the uncertain-syntax case stays denied where no
  pre-execute hook exists.
- New settings: `unattendedPolicies` and an explicit `unattended` flag for deployments where
  the policy is not visible. An unknown policy keeps the safe direction and still asks.
- 8 tests for the new behaviour (23 in total).

# Changelog

## 0.1.3

- First public npmjs release under the canonical @goodandready/dsh-approval-gate identity.

- Extend bounded shell analysis to command and process substitutions, backticks, common redirects and here-documents; inspect nested commands.
- Allow ordinary safe reads and route uncertain syntax or execution targets through DSH approval with a visible rule reason and redacted excerpt.
- Keep recognized destructive commands and protected-file writes denied, and request approval before shell-expanded Authorization values reach curl.
- Keep security hooks active when the optional locale service is unavailable.


## 0.1.2

- Inspect bash argv after quote concatenation instead of regex over the raw string.
- Fail closed on unparseable shell (`$IFS`, command substitution, heredoc, unclosed quotes).
- Guard file-write tools against secret paths.
- Tests for block/pass cases. Denial text no longer names a person.
- Ignore `openwiki/` in git.

## 0.1.1

- Initial distribution used an internal package route before the public npmjs identity introduced in 0.1.3.
