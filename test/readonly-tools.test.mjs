import test from "node:test";
import assert from "node:assert/strict";
import { BandsEngine, DEFAULT_READ_ONLY_TOOLS } from "../lib/bands.js";

test("BandsEngine allows all standard read-only inspection tools unconditionally", () => {
  const engine = new BandsEngine();

  for (const tool of DEFAULT_READ_ONLY_TOOLS) {
    assert.equal(engine.evaluate(tool), "allow", `Tool ${tool} should be allowed`);
    assert.equal(engine.isReadOnlyTool(tool), true);
  }
});

test("BandsEngine allows standard inspection commands (cat, head, tail, grep, find)", () => {
  const engine = new BandsEngine();

  const safeCommands = [
    "cat README.md",
    "head -n 20 package.json",
    "tail -f /var/log/app.log",
    "grep -rn 'function' src/",
    "rg --files",
    "find . -name '*.js'",
    "diff -u fileA fileB",
    "stat /etc/hosts",
    "wc -l file.txt",
    "git log -n 5 --oneline",
    "git show HEAD",
    "git branch -a",
  ];

  for (const cmd of safeCommands) {
    assert.equal(engine.evaluate("bash", cmd), "allow", `Command ${cmd} should be allowed`);
    assert.equal(engine.isSafeInspectionCommand(cmd), true);
  }
});

test("BandsEngine supports dynamic registration of read-only tools and allow-globs", () => {
  const engine = new BandsEngine();

  assert.equal(engine.evaluate("custom_scanner"), "unmatched");
  engine.addReadOnlyTool("custom_scanner");
  assert.equal(engine.evaluate("custom_scanner"), "allow");

  assert.equal(engine.evaluate("bash", "docker ps"), "unmatched");
  engine.addAllowGlob("docker ps*");
  assert.equal(engine.evaluate("bash", "docker ps -a"), "allow");
});

