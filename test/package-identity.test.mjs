import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { apply, name as hostName } from "../lib/index.js";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");

test("public package identity matches the host patch", () => {
  const pkg = JSON.parse(read("package.json"));
  assert.equal(pkg.name, "@goodandready/dsh-approval-gate");
  assert.equal(pkg.publishConfig.registry, "https://registry.npmjs.org");
  assert.equal(pkg.publishConfig.access, "public");
  assert.ok(pkg.files.includes("LICENSE"));
  assert.ok(pkg.files.includes("README.ru.md"));
  assert.ok(pkg.files.includes("README.md"));
  assert.ok(pkg.files.includes("README.zh.md"));
  assert.equal(hostName, "dsh-approval-gate");
  assert.ok(read("cordis.patch.yml").includes("name: '@goodandready/dsh-approval-gate'"));
});

test("all runtime library files exist, are included in package files, and contain no drift", () => {
  const pkg = JSON.parse(read("package.json"));
  assert.ok(pkg.files.includes("lib"));
  const libFiles = fs.readdirSync(path.join(root, "lib")).filter((f) => f.endsWith(".js"));
  assert.ok(libFiles.includes("index.js"));
  assert.ok(libFiles.includes("inspect.js"));
  assert.ok(libFiles.includes("messages.js"));
  assert.ok(libFiles.includes("paths.js"));
  assert.ok(libFiles.includes("bands.js"));
  assert.ok(libFiles.includes("breaker.js"));
  assert.ok(libFiles.includes("canonical.js"));
  assert.ok(libFiles.includes("engine.js"));
  assert.ok(libFiles.includes("grants.js"));
  assert.ok(libFiles.includes("tokenizer.js"));
  assert.ok(libFiles.includes("inspect-env.js"));
  assert.ok(libFiles.includes("redact.js"));

  for (const f of libFiles) {
    const lines = read(path.join("lib", f)).split("\n").length;
    assert.ok(lines <= 600, `lib/${f} has ${lines} lines, exceeding 600 limit`);
  }
});

test("guard blocks dangerous bash and passes safe unrelated calls", () => {
  let guard;
  const ctx = { tools: { guard(callback) { guard = callback; return callback; } } };
  apply(ctx);
  assert.equal(typeof guard, "function");
  assert.match(guard({ name: "bash", arguments: { command: "systemctl restart dsh-web" } }), /Blocked by dsh-approval-gate rule/);
  assert.equal(guard({ name: "bash", arguments: { command: "systemctl is-active dsh-web" } }), undefined);
  assert.equal(guard({ name: "bash", arguments: { command: "grep kill-all docs/" } }), undefined);
  assert.equal(guard({ name: "other", arguments: { command: "rm -rf /tmp/x" } }), undefined);
  assert.match(guard({ name: "write", arguments: { path: ".env", contents: "x=1" } }), /Blocked by dsh-approval-gate rule/);
});

test("tracked package files contain no concrete infrastructure paths", () => {
  const libFiles = fs.readdirSync(path.join(root, "lib")).filter((f) => f.endsWith(".js")).map((f) => path.join("lib", f));
  const files = [
    "README.md",
    "README.ru.md",
    "README.zh.md",
    "package.json",
    "cordis.patch.yml",
    ...libFiles,
    ...(fs.existsSync(path.join(root, "docs")) ? fs.readdirSync(path.join(root, "docs"), { recursive: true }).filter((file) => String(file).endsWith(".md")).map((file) => path.join("docs", file)) : []),
  ];
  const markers = ["/" + "home/", "/" + "mnt/", "192." + "168.", "f" + "ile:/"];
  for (const file of files) {
    const abs = path.join(root, file);
    if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) continue;
    const text = fs.readFileSync(abs, "utf8");
    for (const marker of markers) assert.equal(text.includes(marker), false, file + " contains " + marker);
  }
});
