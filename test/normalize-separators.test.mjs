import test from "node:test";
import assert from "node:assert/strict";
import { normalizeSeparators } from "../lib/paths.js";

test("normalizeSeparators converts backslashes to forward slashes", () => {
  assert.equal(normalizeSeparators("foo\\bar\\baz"), "foo/bar/baz");
  assert.equal(normalizeSeparators("C:\\Users\\vadim\\project"), "C:/Users/vadim/project");
});

test("normalizeSeparators collapses redundant slashes and trims trailing slashes", () => {
  assert.equal(normalizeSeparators("foo///bar//baz/"), "foo/bar/baz");
  assert.equal(normalizeSeparators("/var//log///app/"), "/var/log/app");
  assert.equal(normalizeSeparators("/"), "/");
  assert.equal(normalizeSeparators("C:\\"), "C:/");
});

test("normalizeSeparators normalizes Windows drive letters to uppercase", () => {
  assert.equal(normalizeSeparators("d:\\workspace\\repo"), "D:/workspace/repo");
  assert.equal(normalizeSeparators("c:/tmp"), "C:/tmp");
});

test("normalizeSeparators preserves UNC network paths", () => {
  assert.equal(normalizeSeparators("\\\\server\\share\\folder"), "//server/share/folder");
});

test("normalizeSeparators handles empty and non-string inputs safely", () => {
  assert.equal(normalizeSeparators(""), "");
  assert.equal(normalizeSeparators("   "), "");
  assert.equal(normalizeSeparators(null), "");
  assert.equal(normalizeSeparators(undefined), "");
});

