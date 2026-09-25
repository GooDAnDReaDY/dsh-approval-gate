import assert from "node:assert/strict";
import { test } from "node:test";
import { apply, inject } from "../lib/index.js";
import { MESSAGES } from "../lib/messages.js";

test("pre-execute asks for uncertain syntax while tools.guard stays deny-only", async () => {
  let preExecute;
  let guard;
  const logs = [];
  const ctx = {
    get: (name) => name === "locale" ? ({
      register: (_namespace, dictionaries) => assert.deepEqual(dictionaries, MESSAGES),
      bind: (namespace) => (key) => MESSAGES.en[key] || key,
    }) : undefined,
    effect: (effect) => effect(),
    on: (event, listener) => {
      assert.equal(event, "tools/pre-execute");
      preExecute = listener;
    },
    tools: { guard: (listener) => { guard = listener; } },
    logger: { warn: (line) => logs.push(line) },
  };

  apply(ctx, {});
  assert.equal(typeof preExecute, "function");
  assert.equal(typeof guard, "function");

  const uncertain = { name: "bash", arguments: { command: "echo $(grep value" } };
  let nextCalls = 0;
  const decision = await preExecute(uncertain, async () => {
    nextCalls += 1;
    return { kind: "allow" };
  });
  assert.equal(decision.kind, "ask");
  assert.match(decision.reason, /Shell syntax could not be fully inspected/);
  assert.match(decision.reason, /Parse reason: unclosed command substitution/);
  assert.equal(nextCalls, 0);
  assert.equal(guard(uncertain), undefined);

  const dangerous = { name: "bash", arguments: { command: "echo secret=not-real-secret-value > .env" } };
  await preExecute(dangerous, async () => ({ kind: "allow" }));
  const denial = guard(dangerous);
  assert.match(denial, /Blocked by dsh-approval-gate rule/);
  assert.match(denial, /protected secret file/);
  assert.doesNotMatch(denial, /not-real-secret-value/);
  assert.doesNotMatch(logs.join("\n"), /not-real-secret-value/);
  assert.match(logs[0], /secret-write/);
});

test("missing locale service does not block the security hooks", async () => {
  let guard;
  let preExecute;
  const ctx = {
    get: () => undefined,
    effect: (effect) => effect(),
    on: (_event, listener) => { preExecute = listener; },
    tools: { guard: (listener) => { guard = listener; } },
    logger: { warn: () => undefined },
  };

  assert.deepEqual(inject, ["tools"]);
  apply(ctx, {});
  assert.equal(typeof guard, "function");
  assert.equal(typeof preExecute, "function");
  assert.match(guard({ name: "bash", arguments: { command: "rm -rf /tmp/x" } }), /Recursive file deletion/);
  const result = await preExecute(
    { name: "bash", arguments: { command: "echo $(grep value" } },
    async () => ({ kind: "allow" })
  );
  assert.equal(result.kind, "ask");
  assert.match(result.reason, /Shell syntax could not be fully inspected/);
});

test("localization failures fall back to English and are logged", async () => {
  let preExecute;
  const logs = [];
  const ctx = {
    locale: {
      bind: () => () => { throw new Error("translation failure"); },
    },
    effect: (effect) => effect(),
    on: (_event, listener) => { preExecute = listener; },
    tools: { guard: () => undefined },
    logger: { warn: (line) => logs.push(line) },
  };

  apply(ctx, {});
  const result = await preExecute(
    { name: "bash", arguments: { command: "echo $(grep value" } },
    async () => ({ kind: "allow" })
  );
  assert.equal(result.kind, "ask");
  assert.match(result.reason, /Shell syntax could not be fully inspected/);
  assert.ok(logs.length > 0);
  assert.ok(logs.every((line) => /localization lookup failed/.test(line)));
});

test("locale dictionaries cover English, Chinese, and Russian gate messages", () => {
  for (const locale of ["en", "zh", "ru"]) {
    assert.ok(MESSAGES[locale].blockedPrefix);
    assert.ok(MESSAGES[locale].approvalRequired);
    assert.ok(MESSAGES[locale].askUnparseable);
    assert.ok(MESSAGES[locale].ruleRecursiveRm);
  }
  const enKeys = Object.keys(MESSAGES.en).sort();
  const ruKeys = Object.keys(MESSAGES.ru).sort();
  assert.deepEqual(ruKeys, enKeys);
});

test("apply integrates SecurityEngine waterfall into tools.guard and preExecute", async () => {
  let guard;
  let preExecute;
  const ctx = {
    get: () => undefined,
    effect: (fn) => fn(),
    on: (evt, fn) => { preExecute = fn; },
    tools: { guard: (fn) => { guard = fn; } },
    logger: { warn: () => {} },
  };

  apply(ctx, {});
  assert.equal(typeof guard, "function");
  assert.equal(typeof preExecute, "function");

  // P0 Hard Deny
  assert.match(guard({ name: "bash", arguments: { command: "rm -rf /" } }), /Blocked by dsh-approval-gate rule/);

  // P2 Safe allow
  assert.equal(guard({ name: "bash", arguments: { command: "git status" } }), undefined);

  // P4 Ask on uncertain syntax
  const askRes = await preExecute({ name: "bash", arguments: { command: "echo $(grep value" } }, async () => ({ kind: "allow" }));
  assert.equal(askRes.kind, "ask");
});
