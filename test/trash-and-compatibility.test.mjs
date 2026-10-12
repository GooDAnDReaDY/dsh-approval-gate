import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  resolveTrashDir,
  isRmCommand,
  extractRmTargets,
  buildTrashCommand,
  suggestTrashAlternative,
} from "../lib/trash.js";
import {
  ArtifactRegistry,
  normalizeArtifactPath,
} from "../lib/artifacts.js";
import {
  parseAgentsSecurityRules,
  evaluateAgentsRules,
} from "../lib/agents-parser.js";
import {
  detectHarnessCapabilities,
  assertHarnessCompatibility,
  provideServicePolyfill,
  registerHookPolyfill,
} from "../lib/compat.js";
import {
  parseSemver,
  isMajorBump,
  inspectPackageJsonDiff,
  VersionGuard,
} from "../lib/version-guard.js";
import { SecurityEngine } from "../lib/engine.js";

describe("Issue #104: Reversible Trash Move", () => {
  it("resolves isolated session trash directory", () => {
    const dir = resolveTrashDir("/workspace", "sess-123");
    assert.ok(dir.includes(".dsh"));
    assert.ok(dir.includes("trash"));
    assert.ok(dir.includes("sess-123"));
  });

  it("identifies rm commands and extracts target files", () => {
    assert.equal(isRmCommand("rm file.txt"), true);
    assert.equal(isRmCommand("rm -rf node_modules build"), true);
    assert.equal(isRmCommand("ls -la"), false);

    assert.deepEqual(extractRmTargets("rm file.txt"), ["file.txt"]);
    assert.deepEqual(extractRmTargets("rm -rf node_modules dist"), ["node_modules", "dist"]);
    assert.deepEqual(extractRmTargets("rm --recursive /tmp/scratch"), ["/tmp/scratch"]);
  });

  it("builds safe reversible trash move command", () => {
    const moveCmd = buildTrashCommand(["file1.txt", "file2.txt"], ".dsh/trash/s1");
    assert.equal(moveCmd, "mkdir -p .dsh/trash/s1 && mv file1.txt file2.txt .dsh/trash/s1/");
  });

  it("suggests trash alternative for destructive rm executions", () => {
    const suggestion = suggestTrashAlternative("rm -rf temp_data.json", "/project", "session_abc");
    assert.equal(suggestion.isRm, true);
    assert.deepEqual(suggestion.targets, ["temp_data.json"]);
    assert.ok(suggestion.suggestedCommand.includes("mv temp_data.json"));
    assert.ok(suggestion.suggestedCommand.includes(".dsh/trash/session_abc"));
  });

  it("enriches decisions for rm commands with trashAlternative", () => {
    const engine = new SecurityEngine({ defaultVerdict: "ask" });
    const decision = engine.decide(
      { name: "bash", arguments: { command: "rm config.old" } },
      { sessionId: "s-trash" }
    );
    assert.ok(decision.trashAlternative);
    assert.equal(decision.trashAlternative.isRm, true);
    assert.ok(decision.trashAlternative.suggestedCommand.includes("mv config.old"));
  });
});

describe("Issue #100: Session Artifact Registry & Cleanup Whitelist", () => {
  it("normalizes artifact paths correctly", () => {
    assert.equal(normalizeArtifactPath("./temp.log"), "temp.log");
    assert.equal(normalizeArtifactPath("/ws/src/app.js", "/ws"), "src/app.js");
    assert.equal(normalizeArtifactPath("test\\file.txt"), "test/file.txt");
  });

  it("records and checks session artifacts", () => {
    const registry = new ArtifactRegistry({ workspaceDir: "/ws" });
    registry.recordArtifact("s1", "temp1.txt");
    registry.recordArtifact("s1", "temp2.txt");

    assert.equal(registry.isSessionArtifact("s1", "temp1.txt"), true);
    assert.equal(registry.isSessionArtifact("s1", "temp3.txt"), false);
    assert.equal(registry.isSessionArtifact("s2", "temp1.txt"), false);

    assert.equal(registry.areAllSessionArtifacts("s1", ["temp1.txt", "temp2.txt"]), true);
    assert.equal(registry.areAllSessionArtifacts("s1", ["temp1.txt", "permanent.txt"]), false);
  });

  it("auto-allows cleanup of temporary session artifacts in P1 without prompt spam", () => {
    const registry = new ArtifactRegistry();
    registry.recordArtifact("sess-temp", "scratch.py");

    const engine = new SecurityEngine({
      artifactRegistry: registry,
      defaultVerdict: "ask",
    });

    // Cleaning up session artifact -> auto-allowed at P1
    const cleanDecision = engine.decide(
      { name: "bash", arguments: { command: "rm scratch.py" } },
      { sessionId: "sess-temp" }
    );
    assert.equal(cleanDecision.verdict, "allow");
    assert.equal(cleanDecision.stage, "P1");
    assert.equal(cleanDecision.reason, "session-artifact-cleanup");

    // Deleting permanent file not in registry -> asks for confirmation
    const permDecision = engine.decide(
      { name: "bash", arguments: { command: "rm server.js" } },
      { sessionId: "sess-temp" }
    );
    assert.equal(permDecision.verdict, "ask");
  });
});

describe("Issue #91: Project AGENTS.md Security Rules", () => {
  it("parses forbidden commands and protected paths from markdown content", () => {
    const md = `
# Project Overview
Some description.

# Security Rules
- Never run rm -rf
- Do not execute curl https://evil.com
- Do not modify package.json
- Forbidden: sudo apt-get
`;

    const parsed = parseAgentsSecurityRules(md);
    assert.ok(parsed.rules.length >= 3);
    assert.ok(parsed.rules.some((r) => r.type === "command" && r.pattern.includes("rm -rf")));
    assert.ok(parsed.rules.some((r) => r.type === "path" && r.pattern === "package.json"));
  });

  it("evaluates rules and blocks prohibited executions at P0", () => {
    const parsed = parseAgentsSecurityRules(`
## Security Constraints
- Never run \`reboot\`
- Do not modify \`custom-protected.txt\`
`);

    const engine = new SecurityEngine({
      agentsRules: parsed.rules,
    });

    const cmdDecision = engine.decide(
      { name: "bash", arguments: { command: "reboot now" } },
      { sessionId: "s-agents" }
    );
    assert.equal(cmdDecision.verdict, "deny");
    assert.equal(cmdDecision.stage, "P0");
    assert.equal(cmdDecision.reason, "agents-md-prohibited-command");

    const pathDecision = engine.decide(
      { name: "write_to_file", arguments: { TargetFile: "custom-protected.txt" } },
      { sessionId: "s-agents" }
    );
    assert.equal(pathDecision.verdict, "deny");
    assert.equal(pathDecision.stage, "P0");
    assert.equal(pathDecision.reason, "agents-md-prohibited-path");
  });
});

describe("Issue #106: Host Compatibility & Polyfills", () => {
  it("detects runtime capabilities accurately", () => {
    const mockCtx = {
      tools: { list: () => [] },
      locale: { register: () => {} },
      on: () => {},
      provide: () => {},
      version: "4.1.0",
    };

    const caps = detectHarnessCapabilities(mockCtx);
    assert.equal(caps.hasContext, true);
    assert.equal(caps.hasToolsService, true);
    assert.equal(caps.hasPreExecuteHook, true);
    assert.equal(caps.hasProvideApi, true);
    assert.equal(caps.hasLocaleService, true);
    assert.equal(caps.harnessVersion, "4.1.0");

    const assertRes = assertHarnessCompatibility(mockCtx, { requireTools: true });
    assert.equal(assertRes.compatible, true);
    assert.equal(assertRes.issues.length, 0);
  });

  it("identifies incompatible contexts cleanly", () => {
    const res = assertHarnessCompatibility(null);
    assert.equal(res.compatible, false);
    assert.ok(res.issues.length > 0);
  });

  it("provides service polyfill fallback when provide() is missing", () => {
    const legacyCtx = {};
    const service = { status: "ok" };
    const ok = provideServicePolyfill(legacyCtx, "testService", service);
    assert.equal(ok, true);
    assert.equal(legacyCtx.testService, service);
  });

  it("registers hook polyfill safely", () => {
    let hooked = false;
    const ctx = { on: (event, fn) => { hooked = true; return () => {}; } };
    const unsub = registerHookPolyfill(ctx, "test-event", () => {});
    assert.equal(hooked, true);
    assert.equal(typeof unsub, "function");
  });
});

describe("Issue #95: Dependency Version Guard", () => {
  it("parses semver versions correctly", () => {
    assert.deepEqual(parseSemver("18.2.0"), { major: 18, minor: 2, patch: 0 });
    assert.deepEqual(parseSemver("^4.1.2"), { major: 4, minor: 1, patch: 2 });
    assert.deepEqual(parseSemver("~0.1.18"), { major: 0, minor: 1, patch: 18 });
  });

  it("detects major version bump transitions", () => {
    assert.equal(isMajorBump("^18.2.0", "^19.0.0"), true);
    assert.equal(isMajorBump("4.1.0", "5.0.0"), true);
    assert.equal(isMajorBump("18.2.0", "18.3.0"), false);
    assert.equal(isMajorBump("^1.2.0", "^1.2.9"), false);
  });

  it("detects major dependency bumps across package.json sections", () => {
    const oldPkg = {
      dependencies: { react: "^18.2.0", lodash: "^4.17.21" },
      devDependencies: { typescript: "^5.0.0" },
    };
    const newPkg = {
      dependencies: { react: "^19.0.0", lodash: "^4.17.21" },
      devDependencies: { typescript: "^6.0.0" },
    };

    const diff = inspectPackageJsonDiff(oldPkg, newPkg);
    assert.equal(diff.hasMajorBump, true);
    assert.equal(diff.bumps.length, 2);
    assert.equal(diff.bumps[0].pkg, "react");
    assert.equal(diff.bumps[1].pkg, "typescript");
  });

  it("requires human confirmation (ask) when writing breaking major bumps", () => {
    const mockGuard = {
      inspectWrite: (targetPath, content) => {
        if (targetPath.endsWith("package.json") && content.includes('"react": "^19.0.0"')) {
          return { majorBump: true, detail: "react: 18 -> 19" };
        }
        return { majorBump: false };
      },
    };

    const engine = new SecurityEngine({
      versionGuard: mockGuard,
    });

    const decision = engine.decide(
      {
        name: "write_to_file",
        arguments: {
          TargetFile: "package.json",
          CodeContent: '{"dependencies": {"react": "^19.0.0"}}',
        },
      },
      { sessionId: "s-ver" }
    );

    assert.equal(decision.verdict, "ask");
    assert.equal(decision.stage, "P4");
    assert.equal(decision.reason, "major-version-bump");
  });
});
