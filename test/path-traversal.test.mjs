import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { canonicalizeFsPath, isPathTraversal, resolveSafePath } from "../lib/paths.js";
import { inspectExecution, inspectBashCommand } from "../lib/inspect.js";

test("canonicalizeFsPath resolves . and .. segments cleanly", () => {
  assert.equal(canonicalizeFsPath("/var/log/../lib/./app"), "/var/lib/app");
  assert.equal(canonicalizeFsPath("C:/Users/vadim/../john/docs"), "C:/Users/john/docs");
  assert.equal(canonicalizeFsPath("/../../../etc/passwd"), "/etc/passwd");
  assert.equal(canonicalizeFsPath("src/utils/../../package.json"), "package.json");
});

test("isPathTraversal detects relative traversal escaping base directory", () => {
  assert.equal(isPathTraversal("../../etc/shadow", "/workspace/repo"), true);
  assert.equal(isPathTraversal("sub/../../..", "/workspace/repo"), true);
  assert.equal(isPathTraversal("src/index.js", "/workspace/repo"), false);
  assert.equal(isPathTraversal("./sub/dir/../file.txt", "/workspace/repo"), false);
});

test("isPathTraversal detects null-byte and encoded attacks", () => {
  assert.equal(isPathTraversal("safe.txt\0/../etc/passwd", "/workspace"), true);
  assert.equal(isPathTraversal("sub/%2e%2e/etc/passwd", "/workspace"), true);
});

test("resolveSafePath returns structured safety object", () => {
  const safe = resolveSafePath("src/components/Button.jsx", "/workspace/project");
  assert.equal(safe.safe, true);
  assert.equal(safe.canonical, "/workspace/project/src/components/Button.jsx");

  const unsafe = resolveSafePath("../../../etc/passwd", "/workspace/project");
  assert.equal(unsafe.safe, false);
  assert.equal(unsafe.reason, "path-traversal-escape");
});

test("resolveSafePath detects real symlink traversal escape on filesystem", (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gate-symlink-test-"));
  const workspaceDir = path.join(tmpDir, "workspace");
  const outsideDir = path.join(tmpDir, "outside");
  fs.mkdirSync(workspaceDir);
  fs.mkdirSync(outsideDir);
  const secretFile = path.join(outsideDir, "secret.key");
  fs.writeFileSync(secretFile, "PRIVATE_DATA");

  const symlinkPath = path.join(workspaceDir, "link-to-secret");
  try {
    fs.symlinkSync(secretFile, symlinkPath);
    const result = resolveSafePath(symlinkPath, workspaceDir);
    assert.equal(result.safe, false);
    assert.equal(result.reason, "symlink-traversal-escape");
  } catch (err) {
    // If filesystem does not support symlinks in unprivileged mode
    t.skip("symlinks not supported in environment");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("inspectExecution uses resolveSafePath to block path traversal write tools", () => {
  const hit = inspectExecution(
    { name: "write", arguments: { path: "../../outside/passwords.txt", contents: "leak" } },
    { workspaceDir: "/home/app/project" }
  );
  assert.equal(hit.deny, true);
  assert.equal(hit.reason, "path-traversal");
});

test("inspectExecution allows safe writes inside workspaceDir", () => {
  const hit = inspectExecution(
    { name: "write", arguments: { path: "src/utils/logger.js", contents: "export const log = 1;" } },
    { workspaceDir: "/home/app/project" }
  );
  assert.equal(hit.deny, false);
});

test("inspectBashCommand blocks absolute-path redirects outside workspace", () => {
  const hit = inspectBashCommand("echo bad > /etc/cron.d/job", 0, { workspaceDir: "/workspace/project" });
  assert.equal(hit.deny, true);
  assert.equal(hit.reason, "path-traversal");

  const allowedDev = inspectBashCommand("echo 1 > /dev/null", 0, { workspaceDir: "/workspace/project" });
  assert.equal(allowedDev.deny, false);

  const allowedTmp = inspectBashCommand("echo 1 > /tmp/output.log", 0, { workspaceDir: "/workspace/project" });
  assert.equal(allowedTmp.deny, false);

  const allowedInside = inspectBashCommand("echo 1 > /workspace/project/test.txt", 0, { workspaceDir: "/workspace/project" });
  assert.equal(allowedInside.deny, false);
});
