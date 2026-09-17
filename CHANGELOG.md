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
