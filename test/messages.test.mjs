import assert from "node:assert/strict";
import { test } from "node:test";
import { MESSAGES, denyMessage, askMessage } from "../lib/messages.js";

test("locale dictionaries cover all keys identically across EN and ZH (Russian delegated to dsh-russian-lang)", () => {
  const enKeys = Object.keys(MESSAGES.en).sort();
  const zhKeys = Object.keys(MESSAGES.zh).sort();

  assert.deepEqual(zhKeys, enKeys, "ZH keys must match EN keys");
  assert.equal(MESSAGES.ru, undefined, "RU dictionary must not be hardcoded in plugin (per DSH standard)");
  assert.ok(enKeys.includes("rulePathTraversal"));
  assert.ok(enKeys.includes("ruleEnvDumpLeak"));
  assert.ok(enKeys.includes("hintPathTraversal"));
  assert.ok(enKeys.includes("hintEnvDumpLeak"));
});

test("denyMessage appends localized contextual hints when available", () => {
  const hit = { deny: true, reason: "path-traversal", snippet: "../../etc/passwd" };
  const msgEn = denyMessage(hit, "", (k) => MESSAGES.en[k] || k);
  assert.ok(msgEn.includes("Directory traversal attack detected"));
  assert.ok(msgEn.includes("Hint: Keep operations strictly within the project directory"));

  // External translation (e.g. delegated to dsh-russian-lang)
  const mockRu = {
    blockedPrefix: "Заблокировано правилом dsh-approval-gate",
    rulePathTraversal: "Обнаружена попытка обхода каталогов",
    hintPrefix: "Подсказка",
    hintPathTraversal: "Ограничьте операции пределами рабочего каталога",
  };
  const msgRu = denyMessage(hit, "", (k) => mockRu[k] || k);
  assert.ok(msgRu.includes("Обнаружена попытка обхода каталогов"));
  assert.ok(msgRu.includes("Подсказка: Ограничьте операции пределами рабочего каталога"));

  const msgZh = denyMessage(hit, "", (k) => MESSAGES.zh[k] || k);
  assert.ok(msgZh.includes("检测到路径穿越攻击"));
  assert.ok(msgZh.includes("建议: 请将操作限制在项目根目录内"));
});

test("denyMessage handles env dump leaks and session breaker hints", () => {
  const mockRu = {
    blockedPrefix: "Заблокировано правилом dsh-approval-gate",
    ruleEnvDumpLeak: "Попытка утечки переменных окружения",
    hintPrefix: "Подсказка",
    hintEnvDumpLeak: "Запрашивайте конкретные несекретные переменные",
  };
  const hitEnv = { deny: true, reason: "env-dump-leak", snippet: "env" };
  const msgRu = denyMessage(hitEnv, "", (k) => mockRu[k] || k);
  assert.ok(msgRu.includes("Попытка утечки переменных окружения"));
  assert.ok(msgRu.includes("Запрашивайте конкретные несекретные переменные"));

  const hitBreaker = { deny: true, reason: "circuit-breaker-tripped", snippet: "circuit-breaker" };
  const msgEn = denyMessage(hitBreaker, "", (k) => MESSAGES.en[k] || k);
  assert.ok(msgEn.includes("Circuit breaker tripped"));
  assert.ok(msgEn.includes("Request manual operator approval"));
});
