import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { readAuditEntries } from "../src/audit.js";
import { decisionToHookOutput, mapClaudeTool, runHook } from "../src/hook.js";
import type { ClaudeHookOutput } from "../src/hook.js";
import type { Decision } from "../src/types.js";

const dir = mkdtempSync(join(tmpdir(), "agentguard-hook-"));

function writePolicy(): string {
  const file = join(dir, "policy.json");
  writeFileSync(
    file,
    JSON.stringify({
      defaults: { command: "confirm", file: "allow", network: "confirm" },
      rules: [
        { id: "deny-rm", action: "deny", target: "command", match: { commands: ["\\brm\\s+-rf\\s+[/~]"], mode: "regex" } },
        { id: "allow-git", action: "allow", target: "command", match: { commands: ["git"] } },
        { id: "confirm-sudo", action: "confirm", target: "command", match: { commands: ["\\bsudo\\b"], mode: "regex" } },
        { id: "deny-secrets", action: "deny", target: "file", match: { paths: ["**/.env"] } },
      ],
    }),
    "utf8",
  );
  return file;
}

test("hook: maps Bash to a command request", () => {
  const req = mapClaudeTool({ tool_name: "Bash", tool_input: { command: "git status" }, cwd: "C:\\work" });
  assert.deepEqual(req, { target: "command", command: "git status", cwd: "C:\\work" });
  assert.equal(mapClaudeTool({ tool_name: "Bash", tool_input: { command: "  " } }), null);
  assert.equal(mapClaudeTool({ tool_name: "Bash", tool_input: {} }), null);
});

test("hook: maps file tools with read/write operations", () => {
  assert.deepEqual(mapClaudeTool({ tool_name: "Read", tool_input: { file_path: "src/a.ts" } }), {
    target: "file",
    path: "src/a.ts",
    operation: "read",
  });
  assert.deepEqual(mapClaudeTool({ tool_name: "Write", tool_input: { file_path: "src/b.ts" } }), {
    target: "file",
    path: "src/b.ts",
    operation: "write",
  });
  assert.deepEqual(mapClaudeTool({ tool_name: "Edit", tool_input: { file_path: "src/c.ts" } }), {
    target: "file",
    path: "src/c.ts",
    operation: "write",
  });
  assert.deepEqual(mapClaudeTool({ tool_name: "NotebookEdit", tool_input: { notebook_path: "nb.ipynb" } }), {
    target: "file",
    path: "nb.ipynb",
    operation: "write",
  });
  assert.equal(mapClaudeTool({ tool_name: "Read", tool_input: {} }), null);
});

test("hook: maps WebFetch and returns null for unknown tools", () => {
  assert.deepEqual(mapClaudeTool({ tool_name: "WebFetch", tool_input: { url: "https://example.com/a" } }), {
    target: "network",
    url: "https://example.com/a",
  });
  assert.equal(mapClaudeTool({ tool_name: "Glob", tool_input: { pattern: "**/*.ts" } }), null);
  assert.equal(mapClaudeTool({ tool_name: "WebFetch", tool_input: {} }), null);
  assert.equal(mapClaudeTool({}), null);
});

test("hook: decision output maps confirm to ask", () => {
  const mk = (action: "allow" | "deny" | "confirm"): Decision => ({
    action,
    ruleId: "r",
    reason: "why",
    request: { target: "command", command: "x" },
  });
  assert.equal(decisionToHookOutput(mk("allow")).hookSpecificOutput.permissionDecision, "allow");
  assert.equal(decisionToHookOutput(mk("deny")).hookSpecificOutput.permissionDecision, "deny");
  assert.equal(decisionToHookOutput(mk("confirm")).hookSpecificOutput.permissionDecision, "ask");
  assert.equal(decisionToHookOutput(mk("deny")).hookSpecificOutput.permissionDecisionReason, "why");
});

test("hook: runHook denies rm -rf and writes the audit entry", () => {
  const policyFile = writePolicy();
  const logFile = join(dir, "deny.jsonl");
  const result = runHook({
    policyPath: policyFile,
    logPath: logFile,
    stdinText: JSON.stringify({
      session_id: "sess-1",
      cwd: "C:\\work",
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_input: { command: "rm -rf /" },
    }),
    stderr: () => {},
  });
  assert.equal(result.exitCode, 0);
  assert.equal(result.logged, true);
  const out = JSON.parse(result.stdout) as ClaudeHookOutput;
  assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
  assert.equal(out.hookSpecificOutput.permissionDecisionReason, 'matched rule "deny-rm"');
  const entries = readAuditEntries(logFile);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].action, "deny");
  assert.equal(entries[0].ruleId, "deny-rm");
  assert.equal(entries[0].source, "hook");
  assert.equal(entries[0].sessionId, "sess-1");
  assert.equal(entries[0].cwd, "C:\\work");
});

test("hook: runHook allows git and logs", () => {
  const policyFile = writePolicy();
  const logFile = join(dir, "allow.jsonl");
  const result = runHook({
    policyPath: policyFile,
    logPath: logFile,
    stdinText: JSON.stringify({ tool_name: "Bash", tool_input: { command: "git status" } }),
    stderr: () => {},
  });
  const out = JSON.parse(result.stdout) as ClaudeHookOutput;
  assert.equal(out.hookSpecificOutput.permissionDecision, "allow");
  assert.equal(readAuditEntries(logFile)[0].ruleId, "allow-git");
});

test("hook: unmapped tools pass through with no output and no log", () => {
  const policyFile = writePolicy();
  const logFile = join(dir, "none.jsonl");
  const result = runHook({
    policyPath: policyFile,
    logPath: logFile,
    stdinText: JSON.stringify({ tool_name: "Glob", tool_input: { pattern: "*.ts" } }),
    stderr: () => {},
  });
  assert.equal(result.stdout, "");
  assert.equal(result.logged, false);
  assert.equal(existsSync(logFile), false);
});

test("hook: missing policy passes through, fail-closed denies", () => {
  const missing = join(dir, "no-such-policy.json");
  const stderrLines: string[] = [];
  const open = runHook({
    policyPath: missing,
    logPath: join(dir, "open.jsonl"),
    stdinText: JSON.stringify({ tool_name: "Bash", tool_input: { command: "git status" } }),
    stderr: (l) => stderrLines.push(l),
  });
  assert.equal(open.stdout, "");
  assert.ok(stderrLines.some((l) => /cannot read policy file/.test(l)));

  const closed = runHook({
    policyPath: missing,
    logPath: join(dir, "closed.jsonl"),
    failClosed: true,
    stdinText: JSON.stringify({ tool_name: "Bash", tool_input: { command: "git status" } }),
    stderr: () => {},
  });
  const out = JSON.parse(closed.stdout) as ClaudeHookOutput;
  assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
});

test("hook: invalid stdin passes through", () => {
  const result = runHook({ stdinText: "{oops", stderr: () => {} });
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, "");
});

test("hook: confirm rules surface as ask", () => {
  const policyFile = writePolicy();
  const result = runHook({
    policyPath: policyFile,
    logPath: join(dir, "sudo.jsonl"),
    stdinText: JSON.stringify({ tool_name: "Bash", tool_input: { command: "sudo npm install" } }),
    stderr: () => {},
  });
  const out = JSON.parse(result.stdout) as ClaudeHookOutput;
  assert.equal(out.hookSpecificOutput.permissionDecision, "ask");
});