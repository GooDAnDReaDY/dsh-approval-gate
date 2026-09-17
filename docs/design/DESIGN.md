# DESIGN.md - dsh-approval-gate

## Product / Purpose
- Назначение: host-only safety guard. Intercepts agent tool calls and denies dangerous shell operations and writes to secret files until the owner gives the explicit approval word `делай`.
- Аудитория: operator of a private DeepSeek Harness profile that needs a last-line command gate.
- Статус: private package `@goodandready-private/dsh-approval-gate`. No public npmjs route.

## User Surfaces
- Web/UI: UI отсутствует на текущем этапе. Host-only plugin; no `lib/client.js`, no settings card.
- DSH UI / settings / slots: none. Config is optional `toolName` / `fileWriteTools` on the patch entry.
- API: none.
- CLI: none. The user-visible surface is the denial string returned from `tools.guard`.
- Документация: README.md, README.zh.md, README.ru.md, docs/.

## Visual Direction
- UI отсутствует на текущем этапе.

## Foundations
- Цвета и роли: not applicable.
- Типографика: not applicable.
- Сетка, отступы, responsive: not applicable.
- Accessibility: denial text is plain Unicode; no color-only meaning.

## Components And States
- Components: `lib/inspect.js` (pure argv/path inspector), `lib/index.js` (Cordis `tools.guard`).
- Loading / empty / error / success: empty or missing bash `command` is allowed (nothing to execute). Unparseable shell is denied. File-write tools without a path are allowed.
- Forms: none.

## User Flows
- Agent calls `bash` with a dangerous argv or unparseable shell -> guard returns a denial; the tool body does not run.
- Agent mentions dangerous words inside `echo`/`grep` arguments -> allowed.
- Agent writes `.env` / `credentials.yaml` / `settings.yaml` / `cordis.patch.yml` via a file-write tool -> denied.
- Owner replies with the approval word `делай` using the host's existing approval flow; this plugin does not implement that word matcher.

## Do / Don't
- Do: inspect argv after quote concatenation, not raw regex over the whole string.
- Do: fail closed on unparseable shell (`$IFS`, command substitution, unclosed quotes, heredoc).
- Don't: treat prose inside `echo`/`grep` as a command.
- Don't: add a settings card or sidebar section unless the owner asks.
- Don't: rename the historical private package scope in this task.

## Locked Design Decisions
- 2026-09-16 - Host-only Russian denial string and approval token `делай` are intentional for this private plugin; no `locale.register`. Reason: the operator workflow is the Russian word `делай`, and there is no browser UI. Review if the plugin is ever published publicly or gains a client half.
- 2026-09-16 - Denial text must not name a specific person; it says `от владельца`. Review if multi-operator wording is needed.
- 2026-09-16 - Interpreter `-c`/`-e` payloads are not a full second language parser. Nested `bash -c` is inspected; `python3 -c "print('rm -rf')"` is allowed. Review if interpreter wrappers become a real bypass in production.
- 2026-09-16 - `AGENTS.md`, `index.md`, `deploy.sh` stay tracked in Gitea (project contract). They stay out of the npm allowlist. `openwiki/` is gitignored. Review only if the Gitea file contract changes.

## Addendum: issue #16 candidate behavior

This addendum records the unreleased candidate behavior; the original 0.1.2 design history above is preserved.

- DSH owns approval prompts. The tools/pre-execute hook asks when shell syntax or a write target cannot be verified; approval=never remains fail-closed.
- tools.guard stays deny-only and blocks recognized dangerous operations. Parse errors are checked for known dangerous command patterns, and other unsupported syntax requests approval.
- Host messages use English and Chinese dictionaries, identify the rule, and redact excerpts. Russian documentation is maintained here; runtime Russian strings remain the responsibility of dsh-russian-lang.
- The bounded analyzer handles substitutions, redirects, pipelines, here-documents and nested expansions. It does not read script files and is not a complete Bash parser.
- Broad allowedRoots/readOnlyBypass configuration and a Gitea token helper remain outside issue #16. The locale service is optional and is read through Cordis ctx.get; missing localization must not prevent the security hooks from loading. Shell-expanded Authorization headers are routed to approval because they expose the value in curl argv.

## Public package migration addendum (0.1.3)

The historical private-package statements and initial Russian operator-word proposal above describe the pre-migration design and are superseded for new installs by this addendum.

- The public package identity is @goodandready/dsh-approval-gate on npmjs.
- Commands with uncertain syntax or targets are passed to DSH native approval. The plugin does not implement an approval word.
- Runtime messages are English and Simplified Chinese; Russian UI text is supplied by dsh-russian-lang.
- Existing destructive-operation and protected-write denies remain deny-only.
- Current supported parsing limits and user-facing behavior are documented in the three localized README files.
