# Changelog

## 0.1.10

- Policy: точное определение сессионной политики апрува в `readKnobs` через `approval.effectivePolicy(session)`, историю событий `session.eventAt` и пресет `danger-full-access` (Refs: #140).
- Execution: корректный пропуск некритичных команд в режиме «Полный доступ» (`never`) без ложного поднятия `ask` и автоматического отказа DSH `Error: the user rejected tool` (Refs: #140).
- Observability: форматирование `sessionTag` с получением строкового идентификатора сессии `session.id` / `session.name` вместо `[object Object]` (Refs: #140).

## 0.1.9

- Inspect: декомпозиция `lib/inspect.js` с выносом `checkEnvExfiltration` в `lib/inspect-env.js`, строгое соблюдение порога 600 строк (Refs: #35).
- Security: автоматическое маскирование и redaction чувствительных данных, токенов и паролей в сетевых URL и аудиторских логах `redactUrl` и `redactCredentials` (Refs: #42).
- Paths: интеграция `resolveSafePath` как основного примитива безопасности файловых путей и защита от symlink и path traversal обходов (Refs: #94, #137).
- Engine: интеграция 5-уровневого каскада принятия решений `SecurityEngine` (P0 Hard-Deny -> P1 Grants -> P2 Static -> P3 LLM -> P4 Ask) в хук `tools/pre-execute` и рантайм-гард `tools.guard` (Refs: #122).
- Messages: расширенная мультиязычная локализация причин блокировки (ru, en, zh) с контекстными подсказками безопасных альтернатив `hintPrefix` и `ruleHints` (Refs: #131).
- Sync: автоматический тест контроля паритета рантайм-файлов и синхронизация метаданных публичных релизов (Refs: #138).

## 0.1.8

- Paths: нормализация разделителей путей `normalizeSeparators` для кроссплатформенной обработки Windows (`\`) и POSIX (`/`) слешей (Refs: #109).
- Paths: канонизация путей и превентивная защита от path traversal обходов (`..`, `.` сегменты) `canonicalizePath` и `isPathTraversal` (Refs: #94).
- Security: блокировка модификации скрытых системных файлов и каталогов конфигурации (`.git`, `.env`, `.ssh`) в путях инструментов и перенаправлениях shell (Refs: #108).
- Security: защита от утечки переменных окружения и секретов через команды `env`, `printenv`, `export` (Refs: #105).
- Bands: безусловное разрешение безопасных read-only инструментов и инспекций файловой системы через Band 1 (`isReadOnlyTool`, `isSafeInspectionCommand`) (Refs: #120).

## 0.1.7

- Canonical: каноническая сериализация вызовов инструментов `canonicalizeCall` со стабильной рекурсивной сортировкой ключей и хэшированием `hashCall` (Refs: #124).
- Grants: хранилище временных сессионных грантов `SessionGrantStore` с ограничением по времени жизни (TTL) и максимальному числу вызовов (`maxUses`) (Refs: #123).
- Grants: поддержка точечных грантов на уровне инструмента, префикса аргументов (`commandPrefix`, `pathPrefix`, `prefix`) и регулярных выражений `argsPattern` (Refs: #132).
- Grants: автоматическая сборка мусора и очистка просроченных/исчерпанных сессионных грантов `prune()` с таймером и счетчиком операций (Refs: #130).
- Breaker: детальное логирование переходов состояний предохранителя сессии `CircuitBreaker` (`active -> tripped -> resumed`), история событий и поддержка подписок `onStateChange` (Refs: #121).

## 0.1.6

- Security: автоматическое раскрытие домашних путей `expandHome` (`~`, `$HOME`, `${HOME}`, `%USERPROFILE%`) в путях файлов, аргументах инструментов записи и перенаправлениях shell (Refs: #114).
- Security: синтаксический разбор составных цепочек shell-команд `splitSubcommands` по операторам `&&`, `||`, `;`, `|`, `&` с сохранением кавычек и подстановок (Refs: #113).
- Security: автоматический предохранитель сессии `CircuitBreaker` (блокировка зацикливания агента при 3 подряд или 20 общих отказах с принудительным запросом человека) (Refs: #110).
- Engine: двухполосная предварительная фильтрация `BandsEngine`: Band 0 (Hard Deny regex) для мгновенной блокировки деструктивных команд и Band 1 (Safe Allow glob) для нулевой задержки на рутинных командах инспекции (Refs: #112).
- Engine: 5-уровневый каскад принятия решений `SecurityEngine` (P0 Hard-Deny -> P1 Grants -> P2 Static Rules -> P3 LLM -> P4 Human Ask) с координацией предохранителя и правил (Refs: #122).

## 0.1.5

- Security: block recursive `rm` with uppercase `-R` and `-Rf` flags in compliance with POSIX standard (Refs: #28).
- Security: inspect `chmod` and `chown` in `inspectArgv`, blocking modifications to protected secret files and recursive changes to root/system paths (Refs: #29).
- Security: inspect `source` and `.` shell built-in commands as script executions, requiring approval for external script files and process substitutions (Refs: #30).
- Security: detect destructive SQL (`DROP`, `TRUNCATE`, `ALTER`) delivered via `heredoc` (`<< EOF`) and pipelines to database clients (Refs: #31).
- Security: block `curl` and `wget` streaming pipelines into interpreter processes like `python`, `node`, `perl`, and `ruby` (Refs: #32).
- Security: expand `isProtectedPath` to protect `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d/`, and SSH `authorized_keys` from writes and redirects (Refs: #33).
- Bugfix: support GNU sed `--in-place=<suffix>` prefix syntax when checking modifications to protected files (Refs: #34).
- Refactor: decompose `lib/inspect.js` below the 600-line guideline by extracting bash tokenization into `lib/tokenizer.js` and message formatters into `lib/messages.js` (Refs: #35).
- Localization: add complete built-in Russian (`ru`) dictionary covering all rules, syntax reasons, and approval prompts in `lib/messages.js` (Refs: #36).

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
