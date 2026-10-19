# Changelog

## 0.1.30

- Fix: Защита от потери данных при rollback нечитаемых существующих файлов (takeSnapshot в lib/snapshots.js проверяет наличие через fs.lstatSync, отличает ENOENT/ENOTDIR от ошибок прав/чтения EACCES/EISDIR, возвращает fail-safe ошибку snapshot-read-failed без создания ложного снапшота; rollbackSnapshot удаляет файл только при явном флаге newlyCreated: true) (Fixes: #188).
- Security: Автоматическое определение и строгая изоляция рабочей директории по умолчанию (getDefaultWorkspaceDir в lib/paths.js проверяет DSH_WORKSPACE, WORKSPACE_DIR и process.cwd(); SnapshotManager и inspectExecution в lib/inspect.js по умолчанию изолируют запись файлов и снапшоты в пределах рабочей директории, предотвращая path-traversal и несанкционированную запись во внешние системные пути) (Fixes: #189).

## 0.1.29

- Fix: Безопасная инжекция сервиса `webServer` через `ctx.inject(["webServer"], ...)` при регистрации REST-маршрутов с защитой от прямого чтения на строгих Cordis Context Proxy в DSH alpha2 (Refs: #186).
- Security: Авторизация и аутентификация всех 8 REST-эндпоинтов в `lib/timeline-service.js` через `isTrustedRequest`, валидацию rejection сервиса `connection`, проверку loopback-хоста и `Sec-Fetch-Site` (Refs: #183).
- Feature: Динамическая синхронизация volatile-настроек через подписку на события `loader/volatile-update` и `config` в `lib/index.js` без необходимости перезапуска хоста DSH (Refs: #183).
- Security: Строгая изоляция путей снапшотов внутри `workspaceDir` через `resolveSafePath` в `SnapshotManager.resolvePath` (`lib/snapshots.js`) с отклонением попыток path traversal и внешних путей (Refs: #183).

## 0.1.28

- Fix: Безопасное чтение версии хоста в lib/compat.js через ctx.get(version) и защищенный доступ без падений на строгих Proxy-контекстах Cordis при отсутствии инжекции version (Refs: #184).

## 0.1.27

- Feature: Интерактивный визуальный редактор правил и белых списков путей (ApprovalGateSettingsCard в lib/client.js, TimelineService endpoints /rules в lib/timeline-service.js, слот settings.plugin.item) (Refs: #49).
- Feature: Интерфейс управления выученными правилами (Learned Rules Manager в lib/client.js, ConfirmationLearner.revoke в lib/learning.js, REST endpoints /learned-rules, /learned-rules/revoke в lib/timeline-service.js) с мгновенным отзывом правил по клику (Refs: #84).
- Feature: Ненавязчивая плавающая статусная плашка (AutoApprovalToast в lib/client.js) при фоновом авто-одобрении операций с авто-скрытием через 3 секунды (Refs: #83).
- Feature: Визуальный цветной бейдж активного режима гейта (GateModeBadge в lib/client.js, endpoint /mode в lib/timeline-service.js, слот toolbar.badge) в тулбаре DSH Web (Refs: #116).

## 0.1.26

- Feature: Встроенный модальный просмотрщик изменений (Unified Diff Panel в lib/diff-viewer.js, lib/client.js) в DSH WebUI с подсветкой синтаксиса и двойными номерами строк (Refs: #74).
- Feature: Сворачивание неизмененных строк (Hunk Folding в lib/diff-viewer.js, lib/client.js) с контекстом и разворачиванием по клику (Refs: #75).
- Feature: Вкладка аудита и одобрений в правой панели сессии DSH (ApprovalTimelineTab в lib/timeline-service.js, lib/client.js, слот conversation.view) (Refs: #82).
- Feature: Сводная карточка итогов раунда (TurnCardTracker в lib/turn-card.js) с отчетом о вызовах и правилах (Refs: #86).
- Feature: Визуальный таймер обратного отсчета до авто-решения в карточке согласования (CountdownBadge в lib/client.js) (Refs: #60).

## 0.1.25

- Security: Асинхронная гонка решения (`raceHumanDecision` в `lib/race-decision.js`) между подтверждением человека и настраиваемым таймером хоста с гарантированной защитой от зависания сессий и fail-closed обработкой `lockedAsk` (Refs: #50).
- Feature: Перехват открытого диалога подтверждения через LLM Pre-emption Claim (`RaceHumanHandle.claim` в `lib/race-decision.js`) с автоматическим закрытием модального окна при быстром утвердительном вердикте модели (Refs: #51).
- Feature: HMR-перезагрузка правил на лету (`RulesHmrWatcher` в `lib/rules-hmr.js`) на стандартном `fs.watch` Node.js с дебаунсом и атомарной перекомпиляцией правил в памяти без перезапуска демона dsh (Refs: #43).
- Security: Маппинг сетевых политик на официальные режимы песочницы DSH (`resolveNetworkPolicy`, `checkNetworkAccess` в `lib/network-sandbox.js`: `read-only` -> `deny-all`, `workspace-write` -> `whitelist-only`, `danger-full-access` -> `allow-all`) (Refs: #41).
- Security: Встроенный локальный HTTP/CONNECT forward proxy (`LocalEgressProxy` в `lib/forward-proxy.js`) для надежного перехвата сетевого egress подпроцессов bash (`HTTP_PROXY`, `ALL_PROXY`) и блокировки несанкционированных хостов (Refs: #39).

## 0.1.24

- Security: Жесткое исключение критических категорий из механизма авто-обучения (`canLearnOperation` в `lib/learning.js`) с гарантированным запретом запоминания деструктивных операций (`rm`), секретов (`.env`, `.ssh`), эскалации прав (`sudo`) и системных путей (Refs: #81).
- Feature: Авто-обучение правилам на основе N-1 ручных подтверждений пользователя (`ConfirmationLearner` в `lib/learning.js`) с автоматическим переводом рутинных операций в `learned-auto-allow` на стадии P1 (Refs: #79).
- Feature: Архитектура независимого ревьюера (Second-Model AI) без права самоодобрения основным агентом (`IndependentReviewer`, `SAFETY_REVIEWER_SYSTEM_PROMPT` в `lib/reviewer.js`) со строгим разделением полномочий (Separation of Duties, Refs: #62).
- Feature: Автономный раннер бенчмарков безопасности (`runEvaluation`, `formatEvaluationReport` в `lib/eval-runner.js`, CLI `bin/eval.mjs`) для объективного замера False Positive Rate (FPR) и False Negative Rate (FNR) с интеграцией в `npm run eval` (Refs: #69).
- Feature: Валидация семантического сходства команд (`canonicalizeCommand`, `isSemanticallyEquivalent`, `validateSemanticSimilarity` в `lib/similarity.js`) с поддержкой эквивалентностей пакетных менеджеров (`npm test` vs `pnpm test`) и Flash-модели (Refs: #85).

## 0.1.23

- Tech-debt: Версионирование схемы хранения сессионных вердиктов (`CURRENT_SCHEMA_VERSION = 3` в `lib/ledger.js`) с полной обратной совместимостью и бесшовной миграцией исторических форматов v1/v2/v3 (`migrateVerdictRecord`) (Refs: #73).
- Feature: Поддержка двухтрековых маркеров (`Dual-Track Markers` в `lib/dualtrack.js`: `TRACK_TYPES.INTERNAL` vs `TRACK_TYPES.EXTERNAL`) для четкого разделения скрытых служебных шагов агента и пользовательских мутаций проекта (Refs: #92).
- Feature: Сессионное переключение режимов гейта (`auto-approval` vs `manual` / `strict` / `hybrid` в `lib/session-modes.js`) на основе активного пресета сессии (`resolveSessionGateMode`, `applySessionModePolicy`, `SessionModeRegistry`) (Refs: #61).
- Feature: Сбор доказательного досье (`Evidence Dossier` в `lib/dossier.js`: инструмент, diff, терминал, исходный промпт юзера) с безопасной санитизацией чувствительных токенов и защитой от переполнения памяти (Refs: #64).
- Security: Детекция отклонения от траектории задачи (`Trajectory Drift Detection` в `lib/drift.js`: `TrajectoryTracker`) с перехватом несанкционированного сканирования сети, поиска учетных данных и системного зондирования вне рамок цели сессии (Refs: #68).

## 0.1.22

- Feature: Наследование разрешений в иерархии субагентов через `parentSession lineage authority` (`LineageManager` в `lib/lineage.js`) с безопасным обходом дерева предков и защитой от циклических ссылок (Refs: #98).
- Feature: Сквозная трассировка вызовов с извлечением и связыванием `callId`, `agentId` и `subagentId` со всеми событиями перехвата, аудита и вердиктов безопасности (Refs: #47).
- Feature: Динамическая генерация и инъекция инструкций безопасности в системный промпт агента (`AUTO_MODE_AGENT_GUIDANCE` в `lib/guidance.js`) с мультиязычной поддержкой (EN/RU/ZH) и идемпотентным маркером (Refs: #99).
- Feature: Автоматическое восстановление при избыточных запросах прав песочницы (`Redundant Sandbox Recovery` в `lib/escalation.js`) с генерацией конкретных рекомендаций по повтору безопасных внутрипроектных команд без `danger-full-access` (Refs: #101).
- Security: Протокол точечной эскалации привилегий (`checkEscalationJustification` в `lib/escalation.js`) с требованием обязательного содержательного обоснования (`justification`, не менее 10 символов) для системных операций (Refs: #107).

## 0.1.21

- Feature: Автоматические легковесные пре-снимки файлов (`Pre-execution Snapshots` в `lib/snapshots.js`) перед выполнением мутирующих инструментов с отслеживанием размера и FIFO-вытеснением по сессиям (Refs: #77).
- Feature: Однократный откат изменений (`Undo this change` / `rollbackSnapshot`) из сохраненного пре-снимка с восстановлением исходного контента или удалением созданного файла (Refs: #76).
- Feature: Двухуровневая очистка файловых снимков (`clearSnapshots` для безопасной очистки текущей сессии без влияния на соседние диалоги vs `clearAllSnapshots` для глобального сброса) (Refs: #78).
- Feature: Многоуровневая категоризация масштаба влияния операций (`Measure Kinds` в `lib/measure-kinds.js`: `local-single`, `workspace-wide`, `system-level`) с обогащением вердикта и фиксацией в аудите (Refs: #97).
- Security: Завершение перехода #163 — перевод конфигурации по умолчанию в строгий fail-closed режим (`defaultVerdict: 'ask'`) для неизвестных команд оболочки (Refs: #172).

## 0.1.20

- Feature: Безопасная альтернатива необратимому удалению (`Reversible Trash Move` в `lib/trash.js`) с переносом удаляемых файлов в изолированную сессионную корзину `<workspace>/.dsh/trash/<session_id>/` вместо деструктивного `rm` (Refs: #104).
- Feature: Реестр сессионных артефактов (`ArtifactRegistry` в `lib/artifacts.js`) для автоматического отслеживания и безопасного разрешения очистки временных файлов текущей сессии на стадии P1 без спама подтверждениями (Refs: #100).
- Security: Парсер проектных правил безопасности из `AGENTS.md` (`lib/agents-parser.js`) с жестким перехватом запрещенных команд и путей на стадии P0 (`agents-md-prohibited-command`, `agents-md-prohibited-path` -> `deny`) (Refs: #91).
- Resilience: Проверка совместимости версий хоста DSH (`assertHarnessCompatibility` в `lib/compat.js`) и безопасные полифилы `provideServicePolyfill` / `registerHookPolyfill` для бесшовной работы на различных версиях Cordis (Refs: #106).
- Security: Страж зависимостей проекта (`VersionGuard` в `lib/version-guard.js`) с автоматическим обнаружением мажорных обновлений в `package.json` и переводом их на ручное подтверждение человеком (`major-version-bump` -> `ask`) (Refs: #95).

## 0.1.19

- Security: Структурированная категоризация рисков операций по 5 стандартизированным бакетам (`READ_ONLY`, `WORKSPACE`, `EGRESS`, `SYSTEM`, `SECRETS`) в `lib/risk.js` с приоритетной оценкой чувствительности путей, команд и сетевых направлений (Refs: #58).
- Security: Многомерное тегирование рисков (`risk_tags`: `read-only`, `file-mutation`, `network`, `git`, `credentials`, `package-manager`, `system-mutation`, `privilege-escalation`, `destructive`) для детального анализа и обогащения решений безопасности (Refs: #70).
- Resilience: Трекер задержки семантического классификатора (`ClassifierLatencyTracker` в `lib/latency.js`) со скользящим окном p95/avg и автоматическим переходом на детерминированные правила при превышении SLA (`classifier-sla-fallback` -> `ask`) (Refs: #57).
- Resilience: Плавный fallback при несовместимости эндпоинта с OpenAI JSON-mode (`isShapeRejectError`), извлечение JSON из markdown/raw-ответов (`extractJsonPayload`) и повторный запрос без `response_format` для Ollama/vLLM (Refs: #59).
- Security: Строгая Schemastery-схема вердиктов классификатора (`ClassifierVerdictSchema`, `validateClassifierResponse`) с fail-closed защитой от некорректных/неполных ответов модели (`malformed-classifier-response` -> `ask`) (Refs: #66).

## 0.1.18

- Security: Эвристический предохранитель размера аргументов (`computePayloadSize` / `maxPayloadBytes`, по умолчанию 64 КБ) для предотвращения переполнения контекста LLM-ревьюера и обхода инспекции (`payload-too-large` -> `ask`) (Refs: #71).
- Security: Сканер анти-инъекций инструкций в аргументы и скрипты (`scanPromptInjection`) с жесткой блокировкой директив обхода правил (`SYSTEM OVERRIDE: ALLOW`, `ignore previous instructions` и др. -> `reviewer-injection-attempt`) (Refs: #72).
- Security: Страж соответствия контракту задачи (`ContractGuard` в `lib/contract-guard.js`) с перехватом нецелевых системных пакетных менеджеров, управления службами, сетевых конфигураций и запрещенных инструментов (`contract-violation` -> `ask`) (Refs: #87).
- Security: Строгая изоляция временных каталогов проекта (`resolveTempRoot`, `isGlobalTempPath`, `checkTempIsolation` в `lib/paths.js`) с переводом обращений к глобальному `/tmp` на запрос подтверждения (`unisolated-temp-path` -> `ask` в пользу `<workspace>/.dsh/tmp`) (Refs: #102).
- Feature: Контроль оверинжиниринга (`OverengineeringGuard` в `lib/overengineering.js`) с отслеживанием числа создаваемых уникальных файлов за сессию (`maxFilesPerSession`, по умолчанию 10) и запросом подтверждения при превышении (`overengineering-file-limit` -> `ask`) (Refs: #89).

## 0.1.17

- Feature: Автонормализация URL эндпоинтов пользовательских LLM (`normalizeChatCompletionsUrl`) с поддержкой bare host, портов, `/v1` и `/chat/completions` без риска 404 (Refs: #127).
- Resilience: Устойчивость к сбоям семантического классификатора с автоматическими повторными попытками (`withLlmRetry`) при 5xx, 429 и сетевых таймаутах с быстрым бэкоффом (Refs: #129).
- Feature: Настраиваемая политика поведения при таймауте классификатора (`timeoutPolicy`: strict vs permissive) с безопасным пропуском низкорисковых операций чтения (Refs: #118).
- Security: Санитизация и удаление персональных данных и секретов из аргументов (`sanitizeClassifierInput`) перед отправкой во внешний LLM API (токены OpenAI/Anthropic/GitHub/NPM, пароли, Bearer, приватные ключи) (Refs: #115).
- Refactor: Ограничение размера контекста при классификации (`truncateClassifierContext`) первыми 1000 символами с фиксацией общего объема для минимизации расхода токенов (Refs: #117).

## 0.1.16

- Audit: Отказоустойчивый аудит с блокировкой (`fail-closed audit`) при невозможности записи в append-only журнал (Refs: #53).
- Audit: Однопроходная обратная ротация лога аудита без амплификации ввода-вывода (`auditRotateContent` до 5 МБ / 5000 строк) с сохранением хвоста (Refs: #54).
- Security: Нестираемые метки очистки журнала аудита (`tombstones`) вместо тихого удаления с сохранением sha256 и непрерывной цепочки событий (Refs: #55).
- Metrics: Счетчики перехватов (`BlockCounters`) и метрики частоты срабатывания правил (по стадиям, вердиктам, категориям и правилам) со snapshot в настройках (Refs: #48).
- Security: Блокировка таймаута на безусловный отказ (`lockedAsk`) для критических операций (sudo, rm -rf, ssh-keys, mkfs, reverse shell) с запретом обхода в unattended режиме (Refs: #52).

## 0.1.15

- Rules: Каскадный декларативный YAML-конфиг правил `rules.yaml` (`.dsh/rules.yaml` в проекте и `~/.dsh/rules.yaml` пользователя) с поддержкой allow/deny/ask политик (Refs: #38).
- Rules: Вынесение каталога встроенных критических угроз нулевого уровня (P0) в отчуждаемый версионируемый каталог `rules/builtin-high-risk.yaml` (Refs: #45).
- Rules: Условные предикаты правил `when` с сопоставлением контекста окружения (ОС `os`, git-ветка `branch`, переменные окружения `env` и инструмент `tool`) с поддержкой отрицания `!` (Refs: #44).
- Performance: Высокоскоростной пре-фильтр ключевых слов `HotwordsMatcher` (rm, kill, shadow, sudoers, curl, format и др.) для микросекундного пропуска безопасных команд (Refs: #93).
- Testing: Корпус тестовых векторов `test/vectors/corpus.json` из 110+ команд с автотестом контроля регрессий (FPR=0, FNR=0) (Refs: #46).

## 0.1.14

- Feature: Режим теневого аудита (`dryRun: true` / `shadowMode: true`) в `Config` и `SecurityEngine` для безопасного тестирования правил на проде без блокировки выполнения процессов агента (Refs: #128).
- Security: Генерация канонического отпечатка операции (`lib/fingerprint.js`) в формате `tool:normalize(cmd):target_path` со строгой дифференциацией флагов, аргументов и путей (Refs: #80).
- Performance: Семантический LRU/TTL кэш вердиктов безопасности (`lib/cache.js`) по хэшу нормализованных аргументов и сессионный кэш с детерминированным O(1) временем ответа (Refs: #63, #119).
- Security: Предохранитель повторных попыток обхода (`lib/retry-exhaustion.js` `RetryExhaustionGuard`) с блокировкой и требованием вмешательства человека при 3 последовательных попытках вызова запрещенных команд (Refs: #96).
- Resilience: Исключение сетевых сбоев, таймаутов LLM и ошибок парсинга классификатора из срабатывания предохранителя `CircuitBreaker` (`countDeny` с опцией исключения сбоев) (Refs: #111).
- Quality: Журнал аномалий и качества сессии (`lib/ledger.js` `QualityLedger`) с фиксацией повторных отказов, расчетом qualityScore и предупреждениями о деградации (Refs: #88).
- Security: Изоляция журнала аудита от контекста сессии (`lib/audit-log.js` `AuditLogger`) с записью в append-only файл `~/.dsh/approval-gate-audit.jsonl` для предотвращения indirect prompt injection (Refs: #56).

## 0.1.13

- Architecture: выделение `CommandDispatcher` (`lib/dispatcher.js`) для полной изоляции синтаксического разбора аргументов и классификации типов инструментов от движка принятия решений `SecurityEngine` (Refs: #133).
- Git: специализированный парсер семантики команд Git (`lib/parsers/git.js`) с разграничением безопасных операций чтения (`status`, `log`, `diff`, `rev-parse`), локальных мутаций (`commit`, `checkout -b`, `add`, `branch`) и деструктивных действий (`reset --hard`, `clean -f`, `branch -D`) (Refs: #125).
- Git: разделение локальных операций и сетевой публикации — автоматическое разрешение локальных коммитов и веток при обязательном запросе подтверждения (`git-remote-push`) для `git push` в удаленный репозиторий (Refs: #103).
- Shell: специализированный парсер конструкций оболочки (`lib/parsers/shell-cmds.js`) для детекции опасных перенаправлений в системные блочные устройства (`/dev/sd*`), защищенные файлы секретов и предотвращения обхода через traversal (Refs: #126).
- Security: `SilentErrorGuard` — детекция маскировки критических ошибок компиляции и сбоев команд через подавление потока stderr (`2>/dev/null`, `&>/dev/null`), принудительный нулевой код возврата (`|| true`, `|| :`, `|| exit 0`) и отключение проверки ошибок (`set +e`) (Refs: #90).
- Security: строгая изоляция агента-ревьюера (`Reviewer`) в режиме read-only без возможности запуска shell-процессов или записи/модификации файлов (Refs: #65).
- Security: предотвращение рекурсивной или системной модификации прав и владельцев (`chmod -R`, `chown -R`, манипуляции над `/`, `/etc`, `/var`, `/usr`, `/root`) (Refs: #65).
- Network: безопасный loopback bypass (`lib/loopback.js`) с нулевой задержкой и автоматическим разрешением запросов к `localhost`, `127.0.0.1`, `::1`, `0.0.0.0` для локальных dev-серверов и тестов (Refs: #40).

## 0.1.12

- Fix: корректная регистрация сервиса `approvalGate` в Cordis через `ctx.provide('approvalGate', ...)` и экспорт `export const provide = ['approvalGate']`, устраняющая ошибку `cannot set property "approvalGate" without provide` при старте хоста DSH.
- Policy: надежное определение режима «Полный доступ» (`danger-full-access` / `never`) в `readKnobs` и `isUnattended` даже при отсутствии предварительного события `approval/policy` в сессии (приоритет пресета и sandbox режима над дефолтным `ask` от `ApprovalService`), предотвращающая ложный отказ `the user rejected tool` на всех командах агента.
- Localization: удаление захардкоженного русского словаря из `lib/messages.js` в строгом соответствии со стандартом разработки DSH плагинов (только `en` и `zh`, русская локализация централизованно обслуживается `dsh-russian-lang`) с защитной обработкой `locale.register` в `apply` (Refs: #153, #162).
- Bands: динамическое расширение списка read-only инструментов из хостового `toolRegistry` (`options.toolRegistry`) с поддержкой аннотаций `readOnly` / `readonly` (Refs: #156).
- Engine: настраиваемый дефолтный вердикт для нераспознанных команд `defaultVerdict` (`allow` по умолчанию, опциональный fail-closed `ask`) с добавлением в схему `Config` (Refs: #163).
- Session: гарантированное извлечение строкового `sessionId` в `resolveSessionId` для любых структур объекта `agent` / `session`.

## 0.1.11

- Security: проверка абсолютных путей перенаправлений shell на выход за пределы рабочего каталога `workspaceDir` с исключением canonical устройств (`/dev/null`) и временных каталогов (`/tmp`) (Refs: #143).
- Security: инспекция инструмента `str_replace_editor` как модификатора файлов с проверкой секретов и границ каталога (Refs: #144).
- Security: блокировка обхода через составные префиксы `{`, `}`, `!` в начале shell-команд (Refs: #147).
- Bands: строгий отказ Band 1 Safe Allow для составных команд, конвейеров и операторов цепочек (`&&`, `||`, `;`, `|`, `>`, `$()`) с перенаправлением на полную сегментную инспекцию (Refs: #155, #158).
- Paths: безопасное раскрытие переменной `$HOME` с привязкой к границе сегмента пути (`/\${HOME\}|\$HOME(?=$|[\/\\])/g`), предотвращающее повреждение путей вроде `/opt/$HOME-backup` (Refs: #154).
- Engine: строгий fail-closed fallback в `P4 Ask` при исключениях семантического классификатора (`reason: 'classifier-error'`) и полная изоляция `decide()` и хуков рантайма в защитные блоки `try/catch` с гарантией `inspect-error` (Refs: #145, #159, #161).
- Breaker: блокировка обхода сработавшего Circuit Breaker в unattended/full-access режиме — взведенный предохранитель принудительно возвращает `deny` вместо пропуска в `next()` (Refs: #157, #160).
- Breaker: ограничение размера истории состояний (`MAX_TRACKED_SESSIONS = 500`, `MAX_SESSION_HISTORY = 100`) и пассивные методы проверки без утечки памяти (Refs: #149).
- Policy: оптимизация сканирования истории событий сессии в `readKnobs` — однопроходный поиск, ограничение глубины до 100 событий и кэширование политики сессии на `_gateCachedPolicy` (Refs: #148).
- Schema: поддержка `.volatile()` на полях конфигурации, явные поля `workspaceDir` и `engine`, полифилл для DSH UI формы настроек и функция разворачивания реактивных боксов `plainConfig` (Refs: #142, #150, #151).
- Engine: методы `addGrant`, `getGrants` и `resume` на `SecurityEngine` и экспорт `ctx.approvalGate` для управления грантами и сбросом предохранителя (Refs: #152).

## 0.1.10

- Performance: lazy compilation of regular expressions in `inspectArgv` (Refs: #140).
- Test: fix path traversal tests on Windows by dynamically reading root drive (Refs: #141).

## 0.1.9

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
