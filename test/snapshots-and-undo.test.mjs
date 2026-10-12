import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

import {
  SnapshotManager,
  DEFAULT_MAX_SNAPSHOTS_PER_SESSION,
  DEFAULT_MAX_SNAPSHOT_BYTES,
} from "../lib/snapshots.js";
import {
  MEASURE_KINDS,
  classifyMeasureKind,
  isSystemLevelExecution,
  isWorkspaceWideExecution,
} from "../lib/measure-kinds.js";
import { SecurityEngine } from "../lib/engine.js";
import { Config } from "../lib/index.js";

test("Issue #77: Pre-execution Snapshots", async (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "snap-test-"));
  const sm = new SnapshotManager({ workspaceDir: tmpDir, maxSnapshotsPerSession: 3, maxSnapshotBytes: 100 });

  await t.test("captures pre-execution snapshot for existing file", () => {
    const file = path.join(tmpDir, "sample.txt");
    fs.writeFileSync(file, "original content", "utf8");

    const snap = sm.takeSnapshot(file, { sessionId: "sess-1", callId: "c-100", tool: "replace_file_content" });
    assert.equal(snap.existed, true);
    assert.equal(snap.content, "original content");
    assert.equal(snap.sessionId, "sess-1");
    assert.equal(snap.callId, "c-100");
    assert.equal(snap.tool, "replace_file_content");
    assert.equal(snap.rolledBack, false);
    assert.ok(snap.id.startsWith("snap_"));
  });

  await t.test("records existed=false for non-existent file", () => {
    const newFile = path.join(tmpDir, "newfile.txt");
    const snap = sm.takeSnapshot(newFile, { sessionId: "sess-1", callId: "c-101", tool: "write_to_file" });
    assert.equal(snap.existed, false);
    assert.equal(snap.content, null);
    assert.equal(snap.size, 0);
  });

  await t.test("flags tooLarge when file exceeds maxSnapshotBytes", () => {
    const bigFile = path.join(tmpDir, "big.txt");
    fs.writeFileSync(bigFile, "a".repeat(200), "utf8");

    const snap = sm.takeSnapshot(bigFile, { sessionId: "sess-1", callId: "c-102", tool: "write_to_file" });
    assert.equal(snap.existed, true);
    assert.equal(snap.tooLarge, true);
    assert.equal(snap.content, null);
  });

  await t.test("evicts oldest snapshot when session exceeds maxSnapshotsPerSession", () => {
    // Current sess-1 has 3 snapshots (c-100, c-101, c-102). Add 4th to trigger FIFO eviction of c-100.
    const file4 = path.join(tmpDir, "file4.txt");
    fs.writeFileSync(file4, "file 4 content", "utf8");
    sm.takeSnapshot(file4, { sessionId: "sess-1", callId: "c-103", tool: "write_to_file" });

    const snapshots = sm.getSnapshots("sess-1");
    assert.equal(snapshots.length, 3);
    assert.equal(sm.getSnapshotByCallId("c-100"), null); // evicted
    assert.ok(sm.getSnapshotByCallId("c-103")); // present
  });

  // Cleanup
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("Issue #76: Undo this change (Rollback)", async (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "snap-undo-"));
  const sm = new SnapshotManager({ workspaceDir: tmpDir });

  await t.test("restores modified file to original snapshot content", () => {
    const target = path.join(tmpDir, "mutate.txt");
    fs.writeFileSync(target, "before edit", "utf8");

    const snap = sm.takeSnapshot(target, { sessionId: "s-undo", callId: "c-edit" });

    // Simulate mutation by tool
    fs.writeFileSync(target, "after edit (broken)", "utf8");
    assert.equal(fs.readFileSync(target, "utf8"), "after edit (broken)");

    // Rollback via callId
    const res = sm.rollbackSnapshot("c-edit");
    assert.equal(res.success, true);
    assert.equal(res.snapshotId, snap.id);
    assert.equal(fs.readFileSync(target, "utf8"), "before edit");
  });

  await t.test("deletes newly created file on rollback", () => {
    const createdFile = path.join(tmpDir, "created.txt");
    // Snapshot before creation (existed: false)
    const snap = sm.takeSnapshot(createdFile, { sessionId: "s-undo", callId: "c-create" });
    assert.equal(snap.existed, false);

    // Simulate creation
    fs.writeFileSync(createdFile, "brand new file", "utf8");
    assert.ok(fs.existsSync(createdFile));

    // Rollback deletes the file
    const res = sm.rollbackSnapshot(snap.id);
    assert.equal(res.success, true);
    assert.equal(fs.existsSync(createdFile), false);
  });

  await t.test("rejects double rollback cleanly", () => {
    const target = path.join(tmpDir, "double.txt");
    fs.writeFileSync(target, "initial", "utf8");
    const snap = sm.takeSnapshot(target, { sessionId: "s-undo" });

    const res1 = sm.rollbackSnapshot(snap.id);
    assert.equal(res1.success, true);

    const res2 = sm.rollbackSnapshot(snap.id);
    assert.equal(res2.success, false);
    assert.equal(res2.error, "snapshot-already-rolled-back");
  });

  await t.test("fails rollback if snapshot exceeded size limit", () => {
    const limitSm = new SnapshotManager({ workspaceDir: tmpDir, maxSnapshotBytes: 10 });
    const target = path.join(tmpDir, "oversize.txt");
    fs.writeFileSync(target, "very long string exceeding 10 bytes", "utf8");
    const snap = limitSm.takeSnapshot(target, { sessionId: "s-undo" });
    assert.equal(snap.tooLarge, true);

    const res = limitSm.rollbackSnapshot(snap.id);
    assert.equal(res.success, false);
    assert.equal(res.error, "snapshot-size-limit-exceeded");
  });

  // Cleanup
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("Issue #78: Dual-level Snapshot Cleanup", async (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "snap-clean-"));
  const sm = new SnapshotManager({ workspaceDir: tmpDir });

  const f1 = path.join(tmpDir, "f1.txt");
  const f2 = path.join(tmpDir, "f2.txt");
  fs.writeFileSync(f1, "hello 1", "utf8");
  fs.writeFileSync(f2, "hello 2", "utf8");

  sm.takeSnapshot(f1, { sessionId: "sess-A" });
  sm.takeSnapshot(f2, { sessionId: "sess-B" });

  await t.test("clearSnapshots clears only specified session", () => {
    assert.equal(sm.getSnapshots("sess-A").length, 1);
    assert.equal(sm.getSnapshots("sess-B").length, 1);

    const res = sm.clearSnapshots("sess-A");
    assert.equal(res.cleared, 1);
    assert.equal(res.sessionId, "sess-A");

    // sess-A is empty, sess-B is untouched
    assert.equal(sm.getSnapshots("sess-A").length, 0);
    assert.equal(sm.getSnapshots("sess-B").length, 1);
  });

  await t.test("clearAllSnapshots wipes all sessions", () => {
    const statsBefore = sm.getStats();
    assert.equal(statsBefore.totalSnapshots, 1);

    const res = sm.clearAllSnapshots();
    assert.equal(res.cleared, 1);

    const statsAfter = sm.getStats();
    assert.equal(statsAfter.totalSnapshots, 0);
    assert.equal(statsAfter.sessionCount, 0);
  });

  // Cleanup
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("Issue #97: Multi-level Impact Scale (Measure Kinds)", async (t) => {
  await t.test("classifies single-file operations as local-single", () => {
    assert.equal(
      classifyMeasureKind({ name: "view_file", arguments: { targetPath: "src/index.js" } }),
      MEASURE_KINDS.LOCAL_SINGLE
    );
    assert.equal(
      classifyMeasureKind({ name: "write_to_file", arguments: { TargetFile: "src/button.jsx" } }),
      MEASURE_KINDS.LOCAL_SINGLE
    );
    assert.equal(
      classifyMeasureKind({ name: "bash", arguments: { command: "cat package.json" } }),
      MEASURE_KINDS.LOCAL_SINGLE
    );
    assert.equal(
      classifyMeasureKind({ name: "bash", arguments: { command: "git status" } }),
      MEASURE_KINDS.LOCAL_SINGLE
    );
  });

  await t.test("classifies repo-wide operations as workspace-wide", () => {
    assert.equal(
      classifyMeasureKind({ name: "bash", arguments: { command: "npm install @deepseek-ai/cordis" } }),
      MEASURE_KINDS.WORKSPACE_WIDE
    );
    assert.equal(
      classifyMeasureKind({ name: "bash", arguments: { command: "git checkout -b feat/new-work" } }),
      MEASURE_KINDS.WORKSPACE_WIDE
    );
    assert.equal(
      classifyMeasureKind({ name: "bash", arguments: { command: "git merge main" } }),
      MEASURE_KINDS.WORKSPACE_WIDE
    );
    assert.equal(
      classifyMeasureKind({ name: "bash", arguments: { command: "rm -rf build/" } }),
      MEASURE_KINDS.WORKSPACE_WIDE
    );
    assert.equal(
      isWorkspaceWideExecution({ name: "bash", arguments: { command: "cargo build --release" } }),
      true
    );
  });

  await t.test("classifies OS and network operations as system-level", () => {
    assert.equal(
      classifyMeasureKind({ name: "bash", arguments: { command: "sudo systemctl restart dsh-web" } }),
      MEASURE_KINDS.SYSTEM_LEVEL
    );
    assert.equal(
      classifyMeasureKind({ name: "bash", arguments: { command: "curl -s https://example.com/api" } }),
      MEASURE_KINDS.SYSTEM_LEVEL
    );
    assert.equal(
      classifyMeasureKind({ name: "bash", arguments: { command: "cat /etc/shadow" } }),
      MEASURE_KINDS.SYSTEM_LEVEL
    );
    assert.equal(
      classifyMeasureKind({ name: "read_url_content", arguments: { url: "https://example.com" } }),
      MEASURE_KINDS.SYSTEM_LEVEL
    );
    assert.equal(
      isSystemLevelExecution({ name: "bash", arguments: { command: "apt-get update" } }),
      true
    );
  });

  await t.test("SecurityEngine enriches decision with measureKind", () => {
    const engine = new SecurityEngine();
    const d1 = engine.decide({ name: "view_file", arguments: { targetPath: "README.md" } });
    assert.equal(d1.measureKind, "local-single");

    const d2 = engine.decide({ name: "bash", arguments: { command: "git checkout -b branch-x" } });
    assert.equal(d2.measureKind, "workspace-wide");

    const d3 = engine.decide({ name: "bash", arguments: { command: "sudo whoami" } });
    assert.equal(d3.measureKind, "system-level");
  });
});

test("Issue #172: Fail-closed defaultVerdict ('ask')", async (t) => {
  await t.test("SecurityEngine defaults to fail-closed 'ask' without options", () => {
    const engine = new SecurityEngine();
    const res = engine.decide({ name: "bash", arguments: { command: "unregistered-proprietary-cmd --arg" } });
    assert.equal(res.verdict, "ask");
    assert.equal(res.stage, "P4");
    assert.equal(res.reason, "unmatched-ask");
  });

  await t.test("SecurityEngine defaultVerdict 'allow' explicitly permits unclassified commands", () => {
    const engine = new SecurityEngine({ defaultVerdict: "allow" });
    const res = engine.decide({ name: "bash", arguments: { command: "unregistered-proprietary-cmd --arg" } });
    assert.equal(res.verdict, "allow");
    assert.equal(res.stage, "P2");
    assert.equal(res.reason, "unmatched-allow");
  });

  await t.test("Config schema defaults defaultVerdict to 'ask'", () => {
    assert.equal(Config.dict.defaultVerdict.meta.default, "ask");
  });
});
