# Changelog

## Unreleased

- Parse shell substitutions, backticks, redirects and here-documents; inspect nested commands.
- Route uncertain syntax through the DSH approval request path while keeping known dangerous operations in the monotonic deny guard.
- Add English and Chinese host messages with visible rule reasons and redacted excerpts.
- Add deny coverage for downloaded shell pipelines, git reset --hard, mkfs and dd writes to devices.
- Request DSH approval before sending shell-expanded authorization values to curl.
- Keep the security hooks active when the optional locale service is unavailable.


## 0.1.2

- Inspect bash argv after quote concatenation instead of regex over the raw string.
- Fail closed on unparseable shell (`$IFS`, command substitution, heredoc, unclosed quotes).
- Guard file-write tools against secret paths.
- Tests for block/pass cases. Denial text no longer names a person.
- Ignore `openwiki/` in git.

## 0.1.1

- Private GitHub Packages identity `@goodandready-private/dsh-approval-gate`.
