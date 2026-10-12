import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

import { LineageManager } from "../lib/lineage.js";
import { generateAgentGuidance, injectAgentGuidance, extractGuidance, GUIDANCE_MARKER } from "../lib/guidance.js";
import {
  isRedundantSandboxRequest,
  buildRedundantSandboxRemediation,
  checkEscalationJustification,
  REDUNDANT_SANDBOX_REASON,
  MISSING_JUSTIFICATION_REASON,
  INSUFFICIENT_JUSTIFICATION_REASON,
} from "../lib/escalation.js";
import { SecurityEngine } from "../lib/engine.js";
import { AuditLogger } from "../lib/audit-log.js";

describe("Issue #98: Subagent Lineage Authority (lib/lineage.js)", () => {
  it("registers lineage hierarchy and resolves root session", () => {
    const lm = new LineageManager();
    assert.equal(lm.registerLineage("sub-1", "root-session"), true);
    assert.equal(lm.registerLineage("sub-2", "sub-1"), true);

    assert.equal(lm.getParent("sub-2"), "sub-1");
    assert.equal(lm.getParent("sub-1"), "root-session");
    assert.equal(lm.getRoot("sub-2"), "root-session");
    assert.deepEqual(lm.getLineage("sub-2"), ["sub-2", "sub-1", "root-session"]);
    assert.equal(lm.hasLineageAuthority("sub-2", "root-session"), true);
    assert.equal(lm.hasLineageAuthority("sub-2", "sub-1"), true);
    assert.equal(lm.hasLineageAuthority("sub-1", "sub-2"), false);
  });

  it("prevents circular lineage references cleanly", () => {
    const lm = new LineageManager();
    assert.equal(lm.registerLineage("a", "a"), false);
    assert.equal(lm.registerLineage("b", "a"), true);
    assert.equal(lm.registerLineage("c", "b"), true);
    // Attempt to make a circular loop: a -> c
    assert.equal(lm.registerLineage("a", "c"), false);
  });

  it("resolves effective policy traversing up the lineage chain", () => {
    const lm = new LineageManager();
    lm.registerLineage("child", "parent");
    lm.registerLineage("parent", "root");

    const policyStore = new Map([
      ["root", "unattended"],
    ]);

    const result = lm.resolveEffectivePolicy("child", (id) => policyStore.get(id));
    assert.ok(result);
    assert.equal(result.policy, "unattended");
    assert.equal(result.sourceSessionId, "root");
    assert.equal(result.inherited, true);

    // If child has its own policy, child's policy takes precedence
    policyStore.set("child", "manual");
    const childResult = lm.resolveEffectivePolicy("child", (id) => policyStore.get(id));
    assert.equal(childResult.policy, "manual");
    assert.equal(childResult.sourceSessionId, "child");
    assert.equal(childResult.inherited, false);
  });

  it("clears session and unlinks from parent", () => {
    const lm = new LineageManager();
    lm.registerLineage("child-1", "parent-1");
    lm.clearSession("child-1");
    assert.equal(lm.getParent("child-1"), null);
    assert.deepEqual(lm.getLineage("child-1"), ["child-1"]);
  });
});

describe("Issue #47: Call Traceability and Subagent Linking", () => {
  it("enriches decisions with callId, agentId, and subagentId", () => {
    const engine = new SecurityEngine();
    const execution = {
      name: "bash",
      arguments: { command: "git status" },
      callId: "call_abc_123",
      agentId: "agent-prime",
      subagentId: "subagent-worker-1",
    };
    const context = { sessionId: "sess-trace" };

    const decision = engine.decide(execution, context);
    assert.equal(decision.callId, "call_abc_123");
    assert.equal(decision.agentId, "agent-prime");
    assert.equal(decision.subagentId, "subagent-worker-1");
  });

  it("logs callId, agentId, and subagentId in structured audit entries", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gate-audit-trace-"));
    const logPath = path.join(tmpDir, "audit.jsonl");

    try {
      const logger = new AuditLogger({ logPath });
      const record = {
        sessionId: "sess-audit-trace",
        callId: "call-999",
        agentId: "agent-orchestrator",
        subagentId: "subagent-coder",
        execution: { name: "bash", arguments: { command: "npm test" } },
        decision: { verdict: "allow", stage: "P2", reason: "safe-allow" },
      };

      const success = logger.appendAuditLine(record);
      assert.equal(success, true);

      const content = fs.readFileSync(logPath, "utf8");
      const parsed = JSON.parse(content.trim());
      assert.equal(parsed.sessionId, "sess-audit-trace");
      assert.equal(parsed.callId, "call-999");
      assert.equal(parsed.agentId, "agent-orchestrator");
      assert.equal(parsed.subagentId, "subagent-coder");
      assert.equal(parsed.verdict, "allow");
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

describe("Issue #99: Dynamic Agent Guidance Injection (lib/guidance.js)", () => {
  it("generates markdown guidance for EN, RU, and ZH", () => {
    const en = generateAgentGuidance({ language: "en" });
    assert.ok(en.includes(GUIDANCE_MARKER));
    assert.ok(en.includes("Security & Execution Guidance"));
    assert.ok(en.includes("fail-closed"));

    const ru = generateAgentGuidance({ language: "ru" });
    assert.ok(ru.includes(GUIDANCE_MARKER));
    assert.ok(ru.includes("Инструкции безопасности"));

    const zh = generateAgentGuidance({ language: "zh" });
    assert.ok(zh.includes(GUIDANCE_MARKER));
    assert.ok(zh.includes("执行环境安全指引"));
  });

  it("injects guidance into system prompt idempotently", () => {
    const basePrompt = "You are an AI assistant.";
    const injected1 = injectAgentGuidance(basePrompt, { language: "en" });
    assert.ok(injected1.startsWith(basePrompt));
    assert.ok(injected1.includes(GUIDANCE_MARKER));

    // Second injection must not duplicate guidance
    const injected2 = injectAgentGuidance(injected1, { language: "en" });
    assert.equal(injected1, injected2);

    const extracted = extractGuidance(injected2);
    assert.ok(extracted);
    assert.ok(extracted.startsWith(GUIDANCE_MARKER));
  });
});

describe("Issue #101: Redundant Sandbox Recovery (lib/escalation.js)", () => {
  it("identifies redundant danger-full-access requests for internal project commands", () => {
    assert.equal(isRedundantSandboxRequest("git status", "danger-full-access"), true);
    assert.equal(isRedundantSandboxRequest("npm test", "danger-full-access"), true);
    assert.equal(isRedundantSandboxRequest("cat package.json", "danger-full-access"), true);
    assert.equal(isRedundantSandboxRequest("ls -la src", "danger-full-access"), true);

    // Standard non-elevated sandbox is not redundant
    assert.equal(isRedundantSandboxRequest("git status", "sandboxed"), false);

    // System-level or dangerous commands are NOT considered redundant requests
    assert.equal(isRedundantSandboxRequest("sudo apt update", "danger-full-access"), false);
    assert.equal(isRedundantSandboxRequest("systemctl restart dsh", "danger-full-access"), false);
  });

  it("builds localized actionable remediation messages", () => {
    const en = buildRedundantSandboxRemediation("git status", "en");
    assert.ok(en.includes("Redundant sandbox elevation"));
    assert.ok(en.includes("git status"));

    const ru = buildRedundantSandboxRemediation("npm test", "ru");
    assert.ok(ru.includes("Избыточный запрос привилегий"));
    assert.ok(ru.includes("npm test"));
  });

  it("intercepts redundant sandbox requests in waterfall and returns ask with advice", () => {
    const engine = new SecurityEngine({ enableRedundantSandboxRecovery: true });
    const execution = { name: "bash", arguments: { command: "git status" } };
    const context = { sessionId: "sess-sand", sandboxMode: "danger-full-access" };

    const decision = engine.decide(execution, context);
    assert.equal(decision.verdict, "ask");
    assert.equal(decision.reason, REDUNDANT_SANDBOX_REASON);
    assert.equal(decision.redundantSandbox, true);
    assert.ok(decision.detail.includes("Redundant sandbox elevation"));
  });
});

describe("Issue #107: Privilege Escalation Justification Protocol (lib/escalation.js)", () => {
  it("detects when system commands require justification", () => {
    // Missing justification
    const res1 = checkEscalationJustification("curl https://api.example.com", "bash", {}, { requireJustification: true });
    assert.equal(res1.required, true);
    assert.equal(res1.valid, false);
    assert.equal(res1.reason, MISSING_JUSTIFICATION_REASON);

    // Placeholder or too short justification
    const res2 = checkEscalationJustification("curl https://api.example.com", "bash", { justification: "sudo fix" }, { requireJustification: true });
    assert.equal(res2.required, true);
    assert.equal(res2.valid, false);
    assert.equal(res2.reason, INSUFFICIENT_JUSTIFICATION_REASON);

    // Valid concrete justification
    const res3 = checkEscalationJustification("curl https://api.example.com", "bash", {
      justification: "Fetching external API status for deployment readiness",
    }, { requireJustification: true });
    assert.equal(res3.required, true);
    assert.equal(res3.valid, true);
  });

  it("enforces justification requirement in SecurityEngine waterfall", () => {
    const engine = new SecurityEngine({ defaultVerdict: "ask", requireJustification: true });
    const execution = {
      name: "bash",
      arguments: {
        command: "curl https://api.example.com/health",
      },
    };

    // 1. Without justification: must return ask with missing justification reason
    const decWithout = engine.decide(execution, { sessionId: "sess-just" });
    assert.equal(decWithout.verdict, "ask");
    assert.equal(decWithout.reason, MISSING_JUSTIFICATION_REASON);
    assert.ok(decWithout.justificationAdvice);

    // 2. With valid justification: passes justification check (and continues waterfall)
    const decWith = engine.decide(execution, {
      sessionId: "sess-just",
      justification: "Querying external healthcheck endpoint for canary verification",
    });
    // Now reason is not missing-justification
    assert.notEqual(decWith.reason, MISSING_JUSTIFICATION_REASON);
  });
});
