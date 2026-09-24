import test from "node:test";
import assert from "node:assert/strict";
import { canonicalizeCall, canonicalString, hashCall, sortKeys } from "../lib/canonical.js";

test("sortKeys sorts object keys recursively", () => {
  const unordered = {
    z: 1,
    a: {
      c: 3,
      b: [ { y: 2, x: 1 }, 10 ],
    },
  };
  const sorted = sortKeys(unordered);
  assert.deepEqual(Object.keys(sorted), ["a", "z"]);
  assert.deepEqual(Object.keys(sorted.a), ["b", "c"]);
  assert.deepEqual(Object.keys(sorted.a.b[0]), ["x", "y"]);
});

test("canonicalizeCall produces identical structure regardless of key insertion order", () => {
  const callA = {
    name: "bash",
    arguments: {
      command: "ls -la",
      cwd: "/workspace",
      env: { B: "2", A: "1" },
    },
  };

  const callB = {
    name: "bash",
    arguments: {
      env: { A: "1", B: "2" },
      cwd: "/workspace",
      command: "ls -la",
    },
  };

  const canonA = canonicalizeCall(callA);
  const canonB = canonicalizeCall(callB);

  assert.deepEqual(canonA, canonB);
  assert.equal(canonicalString(callA), canonicalString(callB));
  assert.equal(hashCall(callA), hashCall(callB));
});

test("canonicalizeCall handles tool name and raw arguments parameters", () => {
  const call1 = canonicalizeCall("bash", { command: "whoami" });
  const call2 = canonicalizeCall({ tool: "bash", arguments: { command: "whoami" } });
  const call3 = canonicalizeCall({ name: "bash", arguments: { command: "whoami" } });

  assert.deepEqual(call1, call2);
  assert.deepEqual(call2, call3);
  assert.equal(hashCall(call1), hashCall(call3));
});

test("canonicalizeCall handles null, undefined and JSON string arguments", () => {
  const callNull = canonicalizeCall({ name: "bash", arguments: null });
  assert.deepEqual(callNull.arguments, {});

  const callJson = canonicalizeCall("write_file", JSON.stringify({ path: "/tmp/foo", data: "bar" }));
  assert.deepEqual(callJson.arguments, { data: "bar", path: "/tmp/foo" });
});

test("hashCall generates deterministic sha256 hexadecimal hash", () => {
  const hash1 = hashCall({ name: "read_file", arguments: { path: "/app/config.json" } });
  const hash2 = hashCall({ name: "read_file", arguments: { path: "/app/config.json" } });

  assert.equal(typeof hash1, "string");
  assert.equal(hash1.length, 64);
  assert.equal(hash1, hash2);
});
