import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { apply, name as hostName } from "../lib/index.js";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");

test("private package identity matches the host patch", () => {
  const pkg = JSON.parse(read("package.json"));
  assert.equal(pkg.name, "@goodandready-private/dsh-approval-gate");
  assert.equal(pkg.publishConfig.registry, "https://npm.pkg.github.com");
  assert.equal(hostName, "dsh-approval-gate");
  assert.ok(read("cordis.patch.yml").includes("name: '@goodandready-private/dsh-approval-gate'"));
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
  const files = [
    "README.md",
    "package.json",
    "cordis.patch.yml",
    "lib/index.js",
    "lib/inspect.js",
    ...fs.readdirSync(path.join(root, "docs"), { recursive: true })
      .filter((file) => String(file).endsWith(".md"))
      .map((file) => path.join("docs", file)),
  ];
  const markers = ["/" + "home/", "/" + "mnt/", "192." + "168.", "f" + "ile:/"];
  for (const file of files) {
    const abs = path.join(root, file);
    if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) continue;
    const text = fs.readFileSync(abs, "utf8");
    for (const marker of markers) assert.equal(text.includes(marker), false, file + " contains " + marker);
  }
});
