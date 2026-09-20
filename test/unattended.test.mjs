import assert from "node:assert/strict";
import { test } from "node:test";
import { apply, isUnattended, DEFAULT_UNATTENDED_POLICIES } from "../lib/index.js";

/** A context with the services the gate reads, plus captured hooks. */
function contextWith({ policy = "", sandbox = "", locale = false } = {}) {
  const captured = { preExecute: undefined, guard: undefined, logs: [] };
  const services = {
    approval: { config: { policy } },
    shell: { sandboxMode: sandbox },
  };
  const ctx = {
    get: (name) => {
      if (name === "locale") {
        return locale
          ? { register: () => {}, bind: () => (key) => key }
          : undefined;
      }
      return services[name];
    },
    effect: (effect) => effect(),
    on: (event, listener) => {
      assert.equal(event, "tools/pre-execute");
      captured.preExecute = listener;
    },
    tools: { guard: (listener) => { captured.guard = listener; } },
    logger: { warn: (line) => captured.logs.push(line) },
  };
  return { ctx, captured };
}

const UNCERTAIN = { name: "bash", arguments: { command: "echo $(grep value" } };
const DANGEROUS = { name: "bash", arguments: { command: "echo secret=not-real-secret-value > .env" } };

test("with an unanswerable policy the gate does not raise an ask", async () => {
  const { ctx, captured } = contextWith({ policy: "never" });
  apply(ctx, {});

  let nextCalls = 0;
  const decision = await captured.preExecute(UNCERTAIN, async () => {
    nextCalls += 1;
    return { kind: "allow" };
  });
  assert.equal(nextCalls, 1, "the command proceeds instead of waiting for an answer nobody can give");
  assert.deepEqual(decision, { kind: "allow" });
});

test("with an answerable policy the gate still asks", async () => {
  for (const policy of ["ask", "on-request", "auto"]) {
    const { ctx, captured } = contextWith({ policy });
    apply(ctx, {});
    let nextCalls = 0;
    const decision = await captured.preExecute(UNCERTAIN, async () => {
      nextCalls += 1;
      return { kind: "allow" };
    });
    assert.equal(decision.kind, "ask", `policy ${policy} can be answered`);
    assert.match(decision.reason, /Shell syntax could not be fully inspected/);
    assert.equal(nextCalls, 0);
  }
});

test("an invisible policy keeps the safe direction: the gate asks", async () => {
  const { ctx, captured } = contextWith({ policy: "" });
  apply(ctx, {});
  const decision = await captured.preExecute(UNCERTAIN, async () => ({ kind: "allow" }));
  assert.equal(decision.kind, "ask");
});

test("the explicit flag suppresses the ask where the policy is not visible", async () => {
  const { ctx, captured } = contextWith({ policy: "" });
  apply(ctx, { unattended: true });
  let nextCalls = 0;
  await captured.preExecute(UNCERTAIN, async () => {
    nextCalls += 1;
    return { kind: "allow" };
  });
  assert.equal(nextCalls, 1);
});

test("a custom policy list is honoured", async () => {
  const { ctx, captured } = contextWith({ policy: "auto-review" });
  apply(ctx, { unattendedPolicies: ["auto-review"] });
  let nextCalls = 0;
  await captured.preExecute(UNCERTAIN, async () => {
    nextCalls += 1;
    return { kind: "allow" };
  });
  assert.equal(nextCalls, 1, "a listed policy behaves like never");
});

test("denials never depend on the policy", () => {
  for (const policy of ["never", "ask", ""]) {
    const { ctx, captured } = contextWith({ policy });
    apply(ctx, {});
    const denial = captured.guard(DANGEROUS);
    assert.match(denial, /Blocked by dsh-approval-gate rule/, `policy ${policy}`);
    assert.match(denial, /protected secret file/);
    assert.doesNotMatch(denial, /not-real-secret-value/, "the snippet is redacted");
  }
});

test("the uncertain case is still denied when there is no pre-execute hook at all", () => {
  const { ctx, captured } = contextWith({ policy: "never" });
  // a context without `on`: only the guard exists, and it must deny the ask case itself
  delete ctx.on;
  const mounted = [];
  ctx.tools.guard = (listener) => { mounted.push(listener); };
  apply(ctx, {});
  const denial = mounted[0](UNCERTAIN);
  assert.match(denial, /Blocked by dsh-approval-gate rule/);
  assert.equal(captured.preExecute, undefined);
});

test("isUnattended is a pure decision over the policy list", () => {
  assert.deepEqual(DEFAULT_UNATTENDED_POLICIES, ["never"]);
  assert.equal(isUnattended({ policy: "never" }), true);
  assert.equal(isUnattended({ policy: "ask" }), false);
  assert.equal(isUnattended({ policy: "" }), false);
  assert.equal(isUnattended({}), false);
  assert.equal(isUnattended({ policy: "auto-review", unattendedPolicies: ["auto-review"] }), true);
  assert.equal(isUnattended({ policy: "never", unattendedPolicies: [] }), false, "an empty list disables the shortcut");
});
