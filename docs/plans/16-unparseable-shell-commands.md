# План: исправление shell-разбора и отказов dsh-approval-gate

- Issues: Gitea goodandready/dsh-approval-gate#16; conformance-матрица с goodandready/dsh-shadow-auditor#56.
- Цель: распознавать ограниченный набор shell-синтаксиса, передавать неизвестное штатному DSH подтверждению и сохранять жёсткие запреты.
- Вне scope по текущему #16: широкая конфигурация allowedRoots/readOnlyBypass, отдельный Gitea API helper, публикация, deploy, merge и удаление backup по #13.
- Base: origin/main b446a403970a56892d6189f235197356df274f34.
- Ветка/worktree: fix/approval-gate-shell-parse-ask.

## Этапы

1. [x] Изучить issues обоих репозиториев, исходники, локальные правила и DSH ask/guard contract.
2. [x] Обновить #16 и #56 критериями; создать рабочие worktree.
3. [x] Реализовать ограниченный разбор command substitution, backticks, process substitution, heredoc, перенаправлений и вложенных команд.
4. [x] Для неизвестного синтаксиса запрашивать подтверждение через pre-execute; tools.guard оставлен deny-only.
5. [x] Показывать правило и очищенный фрагмент; не писать сырой фрагмент в лог.
6. [x] Различать чтение и запись защищённых путей; подстановка Authorization в curl требует подтверждения, так как значение становится аргументом процесса. Gitea helper остаётся отдельной задачей согласно границам #16.
7. [x] Исправить shadow-auditor #56 отдельной веткой и покрыть общую матрицу.
8. [x] Обновить EN/ZH/RU документацию и дизайн-контракт; проверить allowlist npm, optional locale и fallback.
9. [x] Проверить gate: npm test 15/15; diff --check чист; preflight FAIL=0 WARN=6; npm pack 9 файлов, 17171 байт.
10. [x] Установить финальный кандидат на MiniPC: bundle виден в dump-config, сервис healthy, активного ожидания locale нет; удалить кандидат и архив, проверить профиль DSH_TEST_OK.
11. [ ] Commit/push и PR. Не выполнять merge/deploy/release без отдельного разрешения.

## Результат preflight

Шесть предупреждений: историческое различие имени пакета и plugin id, отсутствие req.method (write-маршрутов нет), внутренние docs/plans/AGENTS.md/index.md/deploy.sh в git, и lib/inspect.js больше 600 строк. FAIL нет.

## MiniPC приёмка

Финальный tarball goodandready-private-dsh-approval-gate-0.1.2.tgz проверен по SHA-256 при передаче. Официальный helper установил плагин во временный профиль; dump-config показал bundle, текущий журнал не показал pending locale, сервис ответил healthy. Helper удалил плагин и tarball; профиль снова active / DSH_TEST_OK. Артефакт в /tmp на MiniAI удалён.
