import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  categorizeRiskBucket,
  extractRiskTags,
  RISK_BUCKETS,
  RISK_TAGS,
} from "../lib/risk.js";
import {
  ClassifierLatencyTracker,
  DEFAULT_CLASSIFIER_SLA_MS,
} from "../lib/latency.js";
import {
  isShapeRejectError,
  extractJsonPayload,
  ClassifierVerdictSchema,
  validateClassifierResponse,
  LlmClassifier,
} from "../lib/classifier.js";
import { SecurityEngine } from "../lib/engine.js";

describe("Issue #58: Structured Risk Buckets", () => {
  it("categorizes read-only inspection commands as READ_ONLY", () => {
    assert.equal(
      categorizeRiskBucket({ name: "bash", arguments: { command: "ls -la" } }),
      RISK_BUCKETS.READ_ONLY
    );
    assert.equal(
      categorizeRiskBucket({ name: "read_file", arguments: { path: "package.json" } }),
      RISK_BUCKETS.READ_ONLY
    );
    assert.equal(
      categorizeRiskBucket({ name: "bash", arguments: { command: "git status" } }),
      RISK_BUCKETS.READ_ONLY
    );
  });

  it("categorizes secret files and env dumps as SECRETS", () => {
    assert.equal(
      categorizeRiskBucket({ name: "write_file", arguments: { path: ".env" } }),
      RISK_BUCKETS.SECRETS
    );
    assert.equal(
      categorizeRiskBucket({ name: "bash", arguments: { command: "printenv" } }),
      RISK_BUCKETS.SECRETS
    );
    assert.equal(
      categorizeRiskBucket({ name: "write_file", arguments: { path: "id_rsa" } }),
      RISK_BUCKETS.SECRETS
    );
  });

  it("categorizes privileged commands and system packages as SYSTEM", () => {
    assert.equal(
      categorizeRiskBucket({ name: "bash", arguments: { command: "sudo apt-get install curl" } }),
      RISK_BUCKETS.SYSTEM
    );
    assert.equal(
      categorizeRiskBucket({ name: "bash", arguments: { command: "systemctl restart nginx" } }),
      RISK_BUCKETS.SYSTEM
    );
    assert.equal(
      categorizeRiskBucket({ name: "bash", arguments: { command: "chmod 777 /etc" } }),
      RISK_BUCKETS.SYSTEM
    );
  });

  it("categorizes outbound network traffic and git push as EGRESS", () => {
    assert.equal(
      categorizeRiskBucket({ name: "bash", arguments: { command: "curl https://example.com" } }),
      RISK_BUCKETS.EGRESS
    );
    assert.equal(
      categorizeRiskBucket({ name: "bash", arguments: { command: "git push origin main" } }),
      RISK_BUCKETS.EGRESS
    );
    assert.equal(
      categorizeRiskBucket({ name: "fetch", arguments: { url: "https://api.external.com" } }),
      RISK_BUCKETS.EGRESS
    );
  });

  it("treats loopback requests as WORKSPACE rather than external EGRESS", () => {
    assert.equal(
      categorizeRiskBucket({ name: "fetch", arguments: { url: "http://127.0.0.1:3000/api" } }),
      RISK_BUCKETS.WORKSPACE
    );
    assert.equal(
      categorizeRiskBucket({ name: "bash", arguments: { command: "curl http://localhost:8080" } }),
      RISK_BUCKETS.WORKSPACE
    );
  });
});

describe("Issue #70: Multi-dimensional Risk Tagging", () => {
  it("extracts file-mutation tags for file modifications", () => {
    const tags = extractRiskTags({ name: "write_file", arguments: { path: "src/app.js" } });
    assert.ok(tags.includes(RISK_TAGS.FILE_MUTATION));
  });

  it("extracts network and git tags for remote git operations", () => {
    const tags = extractRiskTags({ name: "bash", arguments: { command: "git push origin main" } });
    assert.ok(tags.includes(RISK_TAGS.GIT));
    assert.ok(tags.includes(RISK_TAGS.NETWORK));
  });

  it("extracts package-manager and system-mutation tags for package manager commands", () => {
    const tags = extractRiskTags({ name: "bash", arguments: { command: "npm install express" } });
    assert.ok(tags.includes(RISK_TAGS.PACKAGE_MANAGER));
  });

  it("extracts privilege-escalation and destructive tags for sudo rm", () => {
    const tags = extractRiskTags({ name: "bash", arguments: { command: "sudo rm -rf /var/cache" } });
    assert.ok(tags.includes(RISK_TAGS.PRIVILEGE_ESCALATION));
    assert.ok(tags.includes(RISK_TAGS.DESTRUCTIVE));
    assert.ok(tags.includes(RISK_TAGS.FILE_MUTATION));
  });

  it("extracts credentials tag when sensitive tokens or patterns are present", () => {
    const tags = extractRiskTags({ name: "bash", arguments: { command: "export API_KEY=xyz" } });
    assert.ok(tags.includes(RISK_TAGS.CREDENTIALS));
  });
});

describe("Issue #57: Classifier Latency Tracking & SLA Fallback", () => {
  it("calculates sliding window p95 and average accurately", () => {
    const tracker = new ClassifierLatencyTracker({ slaMs: 500, windowSize: 10 });
    for (let i = 1; i <= 10; i++) {
      tracker.recordSample(i * 100);
    }
    const metrics = tracker.getMetrics();
    assert.equal(metrics.count, 10);
    assert.equal(metrics.minMs, 100);
    assert.equal(metrics.maxMs, 1000);
    assert.ok(metrics.avgMs > 500);
    assert.ok(metrics.p95Ms >= 900);
  });

  it("detects SLA degradation and recovers on fast samples", () => {
    const tracker = new ClassifierLatencyTracker({
      slaMs: 200,
      degradeThresholdCount: 3,
      recoveryThresholdCount: 2,
    });
    assert.equal(tracker.isDegraded(), false);

    tracker.recordSample(300);
    tracker.recordSample(400);
    assert.equal(tracker.isDegraded(), false);

    tracker.recordSample(350); // 3rd slow sample
    assert.equal(tracker.isDegraded(), true);

    // Fast samples recovery
    tracker.recordSample(50);
    assert.equal(tracker.isDegraded(), true);
    tracker.recordSample(60);
    assert.equal(tracker.isDegraded(), false);
  });

  it("falls back to deterministic ask verdict when engine detects SLA degradation", async () => {
    const tracker = new ClassifierLatencyTracker({
      slaMs: 100,
      degradeThresholdCount: 2,
    });
    tracker.recordSample(500);
    tracker.recordSample(600);
    assert.ok(tracker.isDegraded());

    let classifierCalled = false;
    const mockClassifier = {
      classify: async () => {
        classifierCalled = true;
        return { verdict: "allow" };
      },
    };

    const engine = new SecurityEngine({
      classifier: mockClassifier,
      latencyTracker: tracker,
    });

    const decision = await engine.decideAsync(
      { name: "bash", arguments: { command: "custom-sync-daemon --remote" } },
      { sessionId: "test-sla" }
    );

    assert.equal(classifierCalled, false);
    assert.equal(decision.verdict, "ask");
    assert.equal(decision.reason, "classifier-sla-fallback");
  });
});

describe("Issue #59: OpenAI JSON-Mode Rejection Fallback & Extraction", () => {
  it("detects shape reject errors accurately", () => {
    assert.ok(isShapeRejectError({ status: 400, message: "Unsupported parameter: response_format" }));
    assert.ok(isShapeRejectError({ message: "Unknown json_object response_format" }));
    assert.ok(isShapeRejectError({ status: 422, message: "Unprocessable schema entity" }));
    assert.equal(isShapeRejectError({ status: 500, message: "Internal server error" }), false);
  });

  it("extracts JSON payload from raw text and markdown fences", () => {
    assert.deepEqual(extractJsonPayload('{"verdict": "allow", "reason": "ok"}'), {
      verdict: "allow",
      reason: "ok",
    });

    assert.deepEqual(
      extractJsonPayload('Here is your verdict:\n```json\n{"verdict": "deny", "reason": "bad"}\n```\nDone'),
      { verdict: "deny", reason: "bad" }
    );

    assert.deepEqual(
      extractJsonPayload('Sure, output: {"verdict": "ask", "reason": "review"} extra stuff'),
      { verdict: "ask", reason: "review" }
    );

    assert.equal(extractJsonPayload("Random text without json"), null);
  });

  it("retries without response_format when endpoint rejects JSON mode", async () => {
    let callCount = 0;
    const mockFetch = async (url, options) => {
      callCount++;
      const body = JSON.parse(options.body);
      if (body.response_format) {
        const err = new Error("Invalid parameter: response_format is unsupported by this model");
        err.status = 400;
        throw err;
      }
      return {
        ok: true,
        json: async () => ({
          choices: [
            {
              message: {
                content: '```json\n{"verdict": "allow", "reason": "fallback-success"}\n```',
              },
            },
          ],
        }),
      };
    };

    const classifier = new LlmClassifier({
      endpoint: "http://127.0.0.1:11434/v1/chat/completions",
      fetch: mockFetch,
    });

    const res = await classifier.classify({ name: "bash", arguments: { command: "ls" } });
    assert.equal(res.verdict, "allow");
    assert.equal(res.reason, "fallback-success");
    assert.equal(callCount, 2);
    assert.equal(classifier.supportsJsonMode, false);
  });
});

describe("Issue #66: Structured Classifier Verdict Validation", () => {
  it("validates valid classifier responses conforming to schema", () => {
    const valid = validateClassifierResponse({
      verdict: "allow",
      reason: "safe read",
      riskScore: 0.1,
      tags: ["read-only"],
    });
    assert.equal(valid.valid, true);
    assert.equal(valid.verdict, "allow");
    assert.equal(valid.reason, "safe read");
    assert.equal(valid.riskScore, 0.1);
  });

  it("rejects non-object or missing verdicts", () => {
    assert.equal(validateClassifierResponse(null).valid, false);
    assert.equal(validateClassifierResponse("invalid").valid, false);
    assert.equal(validateClassifierResponse({ foo: "bar" }).valid, false);
    assert.equal(validateClassifierResponse({ verdict: "unknown" }).valid, false);
  });

  it("fails closed to ask when classifier returns malformed verdict", async () => {
    const mockFetch = async () => ({
      ok: true,
      json: async () => ({
        choices: [
          {
            message: {
              content: '{"not_a_verdict": 123}',
            },
          },
        ],
      }),
    });

    const classifier = new LlmClassifier({
      endpoint: "http://localhost:8080/v1/chat/completions",
      fetch: mockFetch,
    });

    const res = await classifier.classify({ name: "bash", arguments: { command: "cat file.txt" } });
    assert.equal(res.verdict, "ask");
    assert.equal(res.reason, "malformed-classifier-response");
  });
});

describe("Integration: SecurityEngine Decision Enrichment", () => {
  it("enriches decisions with riskBucket and riskTags", () => {
    const engine = new SecurityEngine();
    const decision = engine.decide(
      { name: "bash", arguments: { command: "rm -rf node_modules" } },
      { sessionId: "enrich-test" }
    );
    assert.ok(decision.riskBucket);
    assert.ok(Array.isArray(decision.riskTags));
    assert.ok(decision.riskTags.includes("destructive"));
    assert.ok(decision.riskTags.includes("file-mutation"));
  });
});
