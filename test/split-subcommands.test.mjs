import test from "node:test";
import assert from "node:assert/strict";
import { splitSubcommands } from "../lib/tokenizer.js";

test("splitSubcommands splits simple commands across operators", () => {
  const res1 = splitSubcommands("git status");
  assert.equal(res1.length, 1);
  assert.deepEqual(res1[0].argv, ["git", "status"]);
  assert.equal(res1[0].operator, null);

  const res2 = splitSubcommands("git status && rm -rf /");
  assert.equal(res2.length, 2);
  assert.deepEqual(res2[0].argv, ["git", "status"]);
  assert.equal(res2[0].operator, null);
  assert.deepEqual(res2[1].argv, ["rm", "-rf", "/"]);
  assert.equal(res2[1].operator, "&&");

  const res3 = splitSubcommands("echo 1; cat /etc/passwd; id");
  assert.equal(res3.length, 3);
  assert.deepEqual(res3[0].argv, ["echo", "1"]);
  assert.deepEqual(res3[1].argv, ["cat", "/etc/passwd"]);
  assert.equal(res3[1].operator, ";");
  assert.deepEqual(res3[2].argv, ["id"]);
  assert.equal(res3[2].operator, ";");

  const res4 = splitSubcommands("cat log.txt | grep error | wc -l");
  assert.equal(res4.length, 3);
  assert.deepEqual(res4[0].argv, ["cat", "log.txt"]);
  assert.deepEqual(res4[1].argv, ["grep", "error"]);
  assert.equal(res4[1].operator, "|");
  assert.deepEqual(res4[2].argv, ["wc", "-l"]);
  assert.equal(res4[2].operator, "|");
});

test("splitSubcommands preserves operators inside quotes and subshells", () => {
  const res1 = splitSubcommands("echo 'hello && world' && ls");
  assert.equal(res1.length, 2);
  assert.deepEqual(res1[0].argv, ["echo", "hello && world"]);
  assert.deepEqual(res1[1].argv, ["ls"]);

  const res2 = splitSubcommands('echo "line 1; line 2" | cat');
  assert.equal(res2.length, 2);
  assert.deepEqual(res2[0].argv, ["echo", "line 1; line 2"]);
  assert.deepEqual(res2[1].argv, ["cat"]);
});

test("splitSubcommands handles empty and edge inputs", () => {
  assert.deepEqual(splitSubcommands(""), []);
  assert.deepEqual(splitSubcommands("   "), []);
  assert.deepEqual(splitSubcommands(null), []);
});

test("splitSubcommands formats heredoc markers properly", () => {
  const cmd = "cat <<EOF\nhello\nEOF";
  const res = splitSubcommands(cmd);
  assert.equal(res.length, 1);
  assert.equal(res[0].command.includes("<<EOF"), true);
});
