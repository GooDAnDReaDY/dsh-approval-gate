import test from "node:test";
import assert from "node:assert/strict";
import { canonicalizeFsPath, isPathTraversal, resolveSafePath } from "../lib/paths.js";

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

