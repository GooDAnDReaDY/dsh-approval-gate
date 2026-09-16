# Changelog

## 0.1.2

- Inspect bash argv after quote concatenation instead of regex over the raw string.
- Fail closed on unparseable shell (`$IFS`, command substitution, heredoc, unclosed quotes).
- Guard file-write tools against secret paths.
- Tests for block/pass cases. Denial text no longer names a person.
- Ignore `openwiki/` in git.

## 0.1.1

- Private GitHub Packages identity `@goodandready-private/dsh-approval-gate`.
