import assert from "node:assert/strict";
import { test } from "node:test";
import { apply, isUnattended, readKnobs, resolveSessionId, DEFAULT_UNATTENDED_POLICIES } from "../lib/index.js";
import { sessionTag } from "../lib/messages.js";

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


test("readKnobs resolves session policy via approval.effectivePolicy(session)", () => {
  const session = { id: "sess-123" };
  const execution = { agent: { session } };
  const ctx = {
    get: (name) => {
      if (name === "approval") {
        return {
          config: { policy: "ask" },
          effectivePolicy: (s) => (s === session ? "never" : "ask"),
        };
      }
      return undefined;
    },
  };
  const knobs = readKnobs(ctx, execution);
  assert.equal(knobs.policy, "never");
  assert.equal(isUnattended(knobs), true);
});

test("readKnobs resolves session policy via session event history", () => {
  const events = [
    { type: "turn/start", data: { turn: 1 } },
    { type: "permission/preset", data: { preset: "danger-full-access" } },
    { type: "approval/policy", data: { policy: "never" } },
  ];
  const session = {
    id: "sess-456",
    seq: events.length,
    eventAt: (seq) => events[seq],
  };
  const execution = { agent: { session } };
  const ctx = {
    get: (name) => {
      if (name === "approval") return { config: { policy: "" } };
      return undefined;
    },
  };
  const knobs = readKnobs(ctx, execution);
  assert.equal(knobs.policy, "never");
  assert.equal(isUnattended(knobs), true);
});

test("readKnobs resolves danger-full-access preset from session event history", () => {
  const events = [
    { type: "turn/start", data: { turn: 1 } },
    { type: "permission/preset", data: { preset: "danger-full-access" } },
  ];
  const session = {
    id: "sess-789",
    seq: events.length,
    eventAt: (seq) => events[seq],
  };
  const execution = { agent: { session } };
  const ctx = {
    get: (name) => {
      if (name === "approval") return { config: { policy: "" } };
      return undefined;
    },
  };
  const knobs = readKnobs(ctx, execution);
  assert.equal(knobs.policy, "never");
  assert.equal(isUnattended(knobs), true);
});

test("full-access session permits uncertain commands in pre-execute without raising ask", async () => {
  const events = [
    { type: "permission/preset", data: { preset: "danger-full-access" } },
  ];
  const session = {
    id: "sess-full-access",
    seq: events.length,
    eventAt: (seq) => events[seq],
  };
  const execution = {
    name: "bash",
    arguments: { command: "mkdir -p /tmp/test && (echo 123 > /tmp/test/out.txt)" },
    agent: { session },
  };

  const { ctx, captured } = contextWith({ policy: "" });
  apply(ctx, {});

  let nextCalled = false;
  const res = await captured.preExecute(execution, async () => {
    nextCalled = true;
    return { kind: "allow" };
  });

  assert.equal(nextCalled, true, "command proceeded automatically under full-access preset");
  assert.deepEqual(res, { kind: "allow" });
});

test("sessionTag formats session id cleanly without [object Object]", () => {
  assert.equal(sessionTag({ agent: "agent-1" }), " (session agent-1)");
  assert.equal(sessionTag({ agent: { session: { id: "sess-abc" } } }), " (session sess-abc)");
  assert.equal(sessionTag({ agent: { session: { name: "sess-def" } } }), " (session sess-def)");
  assert.equal(sessionTag({ agent: { session: "sess-str" } }), " (session sess-str)");
  assert.equal(sessionTag({ agent: { session: {} } }), "");
});

test("tripped breaker in unattended mode is denied instead of allowed", async () => {
  const { ctx, captured } = contextWith({ policy: "never" });
  const customEngine = {
    decide() {
      return {
        verdict: "ask",
        stage: "P4",
        reason: "circuit-breaker-tripped",
        detail: "Circuit breaker tripped due to repeated security denials",
      };
    },
  };
  apply(ctx, { engine: customEngine });

  let nextCalled = false;
  const res = await captured.preExecute(UNCERTAIN, async () => {
    nextCalled = true;
    return { kind: "allow" };
  });

  assert.equal(nextCalled, false, "tripped breaker must NOT bypass in unattended mode");
  assert.match(res, /Blocked by dsh-approval-gate rule/);
  assert.match(res, /Circuit breaker tripped/i);
});


test("danger-full-access preset overrides approval service returning ask (#160, #163)", () => {
  const events = [
    { type: "turn/start", data: { turn: 1 } },
    { type: "permission/preset", data: { preset: "danger-full-access" } },
  ];
  const session = {
    id: "sess-override",
    seq: events.length,
    eventAt: (seq) => events[seq],
  };
  const execution = { agent: { session } };
  const ctx = {
    get: (name) => {
      if (name === "approval") {
        return {
          config: { policy: "ask" },
          effectivePolicy: () => "ask", // host returns ask because no approval/policy was logged
        };
      }
      return undefined;
    },
  };
  const knobs = readKnobs(ctx, execution);
  assert.equal(knobs.preset, "danger-full-access");
  assert.equal(knobs.policy, "never");
  assert.equal(isUnattended(knobs), true);
});

test("danger-full-access sandbox mode sets unattended true even if policy is ask", () => {
  const knobs = { policy: "ask", sandbox: "danger-full-access" };
  assert.equal(isUnattended(knobs), true);
});

test("resolveSessionId extracts clean string id from various agent/session shapes", () => {
  assert.equal(resolveSessionId({ agent: { session: { id: "s-1" } } }), "s-1");
  assert.equal(resolveSessionId({ agent: { session: "s-str" } }), "s-str");
  assert.equal(resolveSessionId({ agent: { session: { sessionId: "s-sid" } } }), "s-sid");
  assert.equal(resolveSessionId({ agent: { id: "a-1" } }), "a-1");
  assert.equal(resolveSessionId({ agent: "a-str" }), "a-str");
  assert.equal(resolveSessionId(null), "default");
  assert.equal(resolveSessionId({}), "default");
});

test("apply uses ctx.provide when present without throwing Cordis provide error", () => {
  let providedName = null;
  let providedValue = null;
  const mockCtx = {
    provide: (name, val) => {
      providedName = name;
      providedValue = val;
    },
    tools: { guard: () => () => {} },
  };
  apply(mockCtx, {});
  assert.equal(providedName, "approvalGate");
  assert.ok(providedValue && typeof providedValue.addGrant === "function");
  assert.ok(providedValue && typeof providedValue.resume === "function");
});
