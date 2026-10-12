// test/telemetry-dossier-drift.test.mjs
// Comprehensive test suite for Iteration 11 (#73, #92, #61, #64, #68).

import test from "node:test";
import assert from "node:assert/strict";

import {
  // #73
  CURRENT_SCHEMA_VERSION,
  SUPPORTED_SCHEMA_VERSIONS,
  migrateVerdictRecord,
  QualityLedger,

  // #92
  TRACK_TYPES,
  classifyTrack,
  isInternalTrack,
  isExternalTrack,

  // #61
  GATE_MODES,
  PRESET_MODE_MAP,
  resolveSessionGateMode,
  applySessionModePolicy,
  SessionModeRegistry,

  // #64
  buildEvidenceDossier,
  formatDossierSummary,
  MAX_PROMPT_CHARS,
  MAX_DIFF_CHARS,
  MAX_OUTPUT_CHARS,

  // #68
  DRIFT_CATEGORIES,
  detectTrajectoryDrift,
  TrajectoryTracker,

  // Engine
  SecurityEngine,
} from "../lib/index.js";

// ============================================================================
// Issue #73: Schema Versioning & Migration Support (v1/v2/v3)
// ============================================================================
test("#73 - exports schema version constants", () => {
  assert.equal(CURRENT_SCHEMA_VERSION, 3);
  assert.deepEqual(SUPPORTED_SCHEMA_VERSIONS, [1, 2, 3]);
});

test("#73 - migrates v1 record to v3 format", () => {
  const v1Record = {
    id: "rec-v1-001",
    verdict: "deny",
    ruleId: "hard-deny-rm",
    timestamp: 1700000000000,
    riskBucket: "high",
  };

  const v3Record = migrateVerdictRecord(v1Record, 3);
  assert.equal(v3Record.schema_version, 3);
  assert.equal(v3Record.id, "rec-v1-001");
  assert.equal(v3Record.verdict, "deny");
  assert.equal(v3Record.reviewDecision, "deny");
  assert.equal(v3Record.bandVerdict, "deny");
  assert.equal(v3Record.mitigation, null);
  assert.equal(v3Record.auditSummary, null);
  assert.equal(v3Record.track, "external");
  assert.equal(v3Record.dossier, null);
  assert.equal(v3Record.driftScore, 0);
  assert.equal(v3Record.driftWarning, false);
});

test("#73 - migrates v2 record to v3 format preserving v2 fields", () => {
  const v2Record = {
    schema_version: 2,
    id: "rec-v2-002",
    verdict: "ask",
    reviewDecision: "ask",
    bandVerdict: "ask",
    mitigation: "request-confirmation",
    auditSummary: "manual confirmation required",
    timestamp: 1700000005000,
  };

  const v3Record = migrateVerdictRecord(v2Record, 3);
  assert.equal(v3Record.schema_version, 3);
  assert.equal(v3Record.reviewDecision, "ask");
  assert.equal(v3Record.mitigation, "request-confirmation");
  assert.equal(v3Record.auditSummary, "manual confirmation required");
  assert.equal(v3Record.track, "external");
  assert.equal(v3Record.driftScore, 0);
  assert.equal(v3Record.driftWarning, false);
});

test("#73 - QualityLedger serializes and deserializes across schema versions", () => {
  const ledger = new QualityLedger();
  ledger.record("sess-test-73", "deny", { reason: "test-deny", tool: "bash" });
  ledger.record("sess-test-73", "allow", { reason: "test-allow", tool: "view_file" });

  const serialized = ledger.serializeSession("sess-test-73");
  assert.equal(serialized.schema_version, 3);
  assert.equal(serialized.totalDecisions, 2);
  assert.equal(serialized.recentEvents.length, 2);
  assert.equal(serialized.recentEvents[0].schema_version, 3);

  // Restore into a fresh ledger
  const newLedger = new QualityLedger();
  newLedger.deserializeSession(serialized);
  const summary = newLedger.getSummary("sess-test-73");
  assert.equal(summary.totalDecisions, 2);
  assert.equal(summary.allowedCount, 1);
  assert.equal(summary.deniedCount, 1);
});

// ============================================================================
// Issue #92: Dual-Track Markers
// ============================================================================
test("#92 - classifies internal and external tracks correctly", () => {
  // Read tools are internal
  assert.equal(classifyTrack("view_file", "", { TargetFile: "src/index.js" }), TRACK_TYPES.INTERNAL);
  assert.equal(classifyTrack("search_web", "", { query: "node docs" }), TRACK_TYPES.INTERNAL);
  assert.equal(classifyTrack("read_url_content", "", { url: "https://example.com" }), TRACK_TYPES.INTERNAL);

  // Operations on scratch/temp paths are internal
  assert.equal(classifyTrack("write_to_file", "", { TargetFile: "/mnt/external/Project/.dsh/tmp/test.txt" }), TRACK_TYPES.INTERNAL);
  assert.equal(classifyTrack("bash", "cat /tmp/debug.log"), TRACK_TYPES.INTERNAL);

  // Read-only shell commands are internal
  assert.equal(classifyTrack("bash", "git status"), TRACK_TYPES.INTERNAL);
  assert.equal(classifyTrack("bash", "git diff"), TRACK_TYPES.INTERNAL);
  assert.equal(classifyTrack("bash", "npm view package-name"), TRACK_TYPES.INTERNAL);

  // Project mutations are external
  assert.equal(classifyTrack("write_to_file", "", { TargetFile: "src/main.js" }), TRACK_TYPES.EXTERNAL);
  assert.equal(classifyTrack("replace_file_content", "", { TargetFile: "lib/engine.js" }), TRACK_TYPES.EXTERNAL);
  assert.equal(classifyTrack("bash", "git push origin main"), TRACK_TYPES.EXTERNAL);
  assert.equal(classifyTrack("bash", "npm publish --access public"), TRACK_TYPES.EXTERNAL);

  // Explicit overrides
  assert.equal(classifyTrack("bash", "npm test", {}, { track: TRACK_TYPES.INTERNAL }), TRACK_TYPES.INTERNAL);
  assert.equal(classifyTrack("view_file", "", {}, { track: TRACK_TYPES.EXTERNAL }), TRACK_TYPES.EXTERNAL);
});

test("#92 - predicates isInternalTrack and isExternalTrack", () => {
  assert.equal(isInternalTrack("internal"), true);
  assert.equal(isInternalTrack("external"), false);
  assert.equal(isInternalTrack({ track: "internal" }), true);
  assert.equal(isInternalTrack({ track: "external" }), false);

  assert.equal(isExternalTrack("external"), true);
  assert.equal(isExternalTrack("internal"), false);
  assert.equal(isExternalTrack({ track: "external" }), true);
  assert.equal(isExternalTrack({ track: "internal" }), false);
});

// ============================================================================
// Issue #61: Session Gate Mode Switching
// ============================================================================
test("#61 - resolves session gate mode from presets", () => {
  assert.equal(resolveSessionGateMode("s1", "sandbox"), GATE_MODES.AUTO);
  assert.equal(resolveSessionGateMode("s2", "prod"), GATE_MODES.STRICT);
  assert.equal(resolveSessionGateMode("s3", "production"), GATE_MODES.STRICT);
  assert.equal(resolveSessionGateMode("s4", "manual"), GATE_MODES.MANUAL);
  assert.equal(resolveSessionGateMode("s5", "dev"), GATE_MODES.HYBRID);
  assert.equal(resolveSessionGateMode("s6", "unknown"), GATE_MODES.HYBRID);
});

test("#61 - SessionModeRegistry manages session modes", () => {
  const reg = new SessionModeRegistry();
  assert.equal(reg.getMode("sess-1", "sandbox"), GATE_MODES.AUTO);
  reg.setMode("sess-1", GATE_MODES.STRICT);
  assert.equal(reg.getMode("sess-1"), GATE_MODES.STRICT);
  reg.clearSession("sess-1");
  assert.equal(reg.getMode("sess-1"), GATE_MODES.HYBRID);
});

test("#61 - applySessionModePolicy auto-approves safe ask in auto mode", () => {
  const askDecision = { verdict: "ask", reason: "unmatched-ask", stage: "P4" };
  const autoResult = applySessionModePolicy(GATE_MODES.AUTO, askDecision, {
    track: TRACK_TYPES.INTERNAL,
    riskBucket: "low",
  });
  assert.equal(autoResult.verdict, "allow");
  assert.equal(autoResult.autoApproved, true);
  assert.equal(autoResult.originalVerdict, "ask");

  // Locked ask is NEVER auto-approved
  const lockedDecision = { verdict: "ask", reason: "critical-operation", lockedAsk: true };
  const lockedResult = applySessionModePolicy(GATE_MODES.AUTO, lockedDecision, {
    track: TRACK_TYPES.INTERNAL,
    lockedAsk: true,
  });
  assert.equal(lockedResult.verdict, "ask");
  assert.equal(lockedResult.autoApproved, undefined);
});

test("#61 - applySessionModePolicy requires confirmation for mutations in strict/manual mode", () => {
  const allowDecision = { verdict: "allow", reason: "safe-allow", stage: "P2" };
  const strictResult = applySessionModePolicy(GATE_MODES.STRICT, allowDecision, {
    track: TRACK_TYPES.EXTERNAL,
    riskBucket: "medium",
  });
  assert.equal(strictResult.verdict, "ask");
  assert.equal(strictResult.manualRequired, true);
  assert.equal(strictResult.originalVerdict, "allow");
});

// ============================================================================
// Issue #64: Evidence Dossier Gathering
// ============================================================================
test("#64 - builds evidence dossier with sanitization and truncation", () => {
  const execution = {
    name: "bash",
    arguments: {
      command: "npm test",
      api_token: "super-secret-12345",
      longArg: "a".repeat(150),
    },
  };
  const context = {
    userPrompt: "x".repeat(300),
    diffSnippet: "+".repeat(500),
    terminalOutput: "out".repeat(200),
    track: "internal",
    riskBucket: "low",
  };

  const dossier = buildEvidenceDossier({ execution, context });
  assert.equal(dossier.toolName, "bash");
  assert.equal(dossier.command, "npm test");
  assert.equal(dossier.argsSummary.api_token, "[REDACTED]");
  assert.ok(dossier.userPrompt.length <= MAX_PROMPT_CHARS);
  assert.ok(dossier.diffSnippet.length <= MAX_DIFF_CHARS);
  assert.ok(dossier.terminalOutput.length <= MAX_OUTPUT_CHARS);
  assert.equal(dossier.track, "internal");
  assert.equal(dossier.riskBucket, "low");

  const summary = formatDossierSummary(dossier);
  assert.ok(summary.includes("tool=bash"));
  assert.ok(summary.includes("track=internal"));
});

// ============================================================================
// Issue #68: Trajectory Drift Detection
// ============================================================================
test("#68 - detects port scanning without network goal as drift", () => {
  const execution = { name: "bash", arguments: { command: "nmap -sS 192.168.1.1" } };
  const context = { userPrompt: "Fix CSS margins in Header component" };

  const drift = detectTrajectoryDrift("s-drift-1", execution, context);
  assert.equal(drift.hasDrift, true);
  assert.equal(drift.category, DRIFT_CATEGORIES.NETWORK_RECON);
  assert.equal(drift.driftWarning, true);
  assert.ok(drift.driftScore >= 0.7);
});

test("#68 - allows port scanning when session goal explicitly mentions network diagnosis", () => {
  const execution = { name: "bash", arguments: { command: "nmap -sS 192.168.1.1" } };
  const context = { userPrompt: "Diagnose network timeout and scan open ports" };

  const drift = detectTrajectoryDrift("s-drift-2", execution, context);
  assert.equal(drift.hasDrift, false);
});

test("#68 - detects credential hunting without credential goal as drift", () => {
  const execution = { name: "bash", arguments: { command: "cat ~/.ssh/id_rsa" } };
  const context = { userPrompt: "Refactor database models" };

  const drift = detectTrajectoryDrift("s-drift-3", execution, context);
  assert.equal(drift.hasDrift, true);
  assert.equal(drift.category, DRIFT_CATEGORIES.CREDENTIAL_HUNT);
  assert.equal(drift.driftWarning, true);
});

test("#68 - TrajectoryTracker integrates with SecurityEngine", () => {
  const engine = new SecurityEngine();
  engine.setSessionGoal("sess-drift-engine", "Run unit tests and check coverage");

  // Suspicious network scan command
  const decision = engine.decide(
    { name: "bash", arguments: { command: "nmap 127.0.0.1" } },
    { sessionId: "sess-drift-engine" }
  );

  assert.equal(decision.verdict, "ask");
  assert.equal(decision.reason, "trajectory-drift-detected");
  assert.ok(decision.drift);
  assert.equal(decision.drift.hasDrift, true);
});

// ============================================================================
// End-to-End Engine Integration for Iteration 11
// ============================================================================
test("Iteration 11 E2E - SecurityEngine enriches decisions with track and dossier", () => {
  const engine = new SecurityEngine();
  const decision = engine.decide(
    { name: "view_file", arguments: { TargetFile: "src/index.js" } },
    { sessionId: "sess-it11-e2e", userPrompt: "Review code" }
  );

  assert.equal(decision.verdict, "allow");
  assert.equal(decision.track, TRACK_TYPES.INTERNAL);
  assert.ok(decision.dossier);
  assert.equal(decision.dossier.toolName, "view_file");
  assert.equal(decision.dossier.track, TRACK_TYPES.INTERNAL);
});

test("Iteration 11 E2E - SecurityEngine applies session gate mode (auto-approval vs manual)", () => {
  const engine = new SecurityEngine();

  // Sandbox session: auto-approves safe internal ask
  engine.setSessionMode("sess-sandbox", GATE_MODES.AUTO);
  const sandboxDec = engine.decide(
    { name: "bash", arguments: { command: "echo internal-check" } },
    { sessionId: "sess-sandbox" }
  );
  assert.equal(sandboxDec.verdict, "allow");

  // Production session: strict enforcement
  engine.setSessionMode("sess-prod", GATE_MODES.STRICT);
  const prodDec = engine.decide(
    { name: "write_to_file", arguments: { TargetFile: "package.json", CodeContent: "{}" } },
    { sessionId: "sess-prod" }
  );
  assert.equal(prodDec.verdict, "ask");
  assert.equal(prodDec.manualRequired, true);
});
