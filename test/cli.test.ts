import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const cliPath = fileURLToPath(new URL("../src/cli.js", import.meta.url));
const baseDir = mkdtempSync(join(tmpdir(), "agentguard-cli-"));

function runCli(args: string[], opts: { cwd?: string; input?: string } = {}): {
  status: number;
  stdout: string;
  stderr: string;
} {
  const r = spawnSync(process.execPath, [cliPath, ...args], {
    cwd: opts.cwd ?? baseDir,
    input: opts.input,
    encoding: "utf8",
  });
  return { status: r.status ?? -1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

function putPolicy(dir: string, name = "agentguard.policy.json"): string {
  const file = join(dir, name);
  writeFileSync(
    file,
    JSON.stringify({
      defaults: { command: "confirm", file: "allow", network: "confirm" },
      rules: [
        { id: "deny-rm", action: "deny", target: "command", match: { commands: ["\\brm\\s+-rf\\s+[/~]"], mode: "regex" }, reason: "blocked" },
        { id: "allow-git", action: "allow", target: "command", match: { commands: ["git"] } },
        { id: "allow-node", action: "allow", target: "command", match: { commands: ["node"] } },
        { id: "deny-secrets", action: "deny", target: "file", match: { paths: ["**/.env"] } },
      ],
    }),
    "utf8",
  );
  return file;
}

test("cli: version prints the package version", () => {
  const r = runCli(["version"]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /agentguard 0\.1\.0/);
});

test("cli: help prints usage", () => {
  const r = runCli(["help"]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /usage: agentguard/);
});

test("cli: unknown command fails", () => {
  const r = runCli(["frobnicate"]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /unknown command "frobnicate"/);
});

test("cli: init writes a starter policy; repeat needs --force", () => {
  const d = mkdtempSync(join(baseDir, "init-"));
  const first = runCli(["init"], { cwd: d });
  assert.equal(first.status, 0);
  assert.ok(existsSync(join(d, "agentguard.policy.json")));

  const again = runCli(["init"], { cwd: d });
  assert.equal(again.status, 1);
  assert.match(again.stderr, /already exists/);

  const forced = runCli(["init", "--force"], { cwd: d });
  assert.equal(forced.status, 0);

  const validate = runCli(["validate"], { cwd: d });
  assert.equal(validate.status, 0);
  assert.match(validate.stdout, /rules: 6 \(allow 2, deny 3, confirm 1\)/);
});

test("cli: validate reports policy errors", () => {
  const d = mkdtempSync(join(baseDir, "bad-"));
  writeFileSync(
    join(d, "agentguard.policy.json"),
    JSON.stringify({ rules: [{ id: "x", action: "explode", target: "command", match: { commands: ["a"] } }] }),
    "utf8",
  );
  const r = runCli(["validate"], { cwd: d });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /action must be one of allow, deny, confirm/);
  assert.match(r.stdout, /result: invalid/);
});

test("cli: check denies a dangerous command with exit 2", () => {
  const d = mkdtempSync(join(baseDir, "check-deny-"));
  putPolicy(d);
  const r = runCli(["check", "--command", "rm -rf /"], { cwd: d });
  assert.equal(r.status, 2);
  assert.match(r.stdout, /decision: DENY/);
  assert.match(r.stdout, /rule: deny-rm/);

  const json = runCli(["check", "--command", "rm -rf /", "--json"], { cwd: d });
  const decision = JSON.parse(json.stdout) as { action: string; ruleId: string };
  assert.equal(decision.action, "deny");
  assert.equal(decision.ruleId, "deny-rm");
});

test("cli: check allows and confirms with the right exit codes", () => {
  const d = mkdtempSync(join(baseDir, "check-codes-"));
  putPolicy(d);
  const allowed = runCli(["check", "--command", "git status"], { cwd: d });
  assert.equal(allowed.status, 0);
  assert.match(allowed.stdout, /decision: ALLOW/);

  const confirm = runCli(["check", "--command", "python setup.py"], { cwd: d });
  assert.equal(confirm.status, 3);
  assert.match(confirm.stdout, /decision: CONFIRM/);
});

test("cli: check works for files and hosts", () => {
  const d = mkdtempSync(join(baseDir, "check-kinds-"));
  putPolicy(d);
  const file = runCli(["check", "--file", "config/.env"], { cwd: d });
  assert.equal(file.status, 2);
  assert.match(file.stdout, /rule: deny-secrets/);

  const writeOk = runCli(["check", "--file", "src/a.ts", "--operation", "write"], { cwd: d });
  assert.equal(writeOk.status, 0);

  const host = runCli(["check", "--host", "api.github.com"], { cwd: d });
  assert.equal(host.status, 3);
  assert.match(host.stdout, /decision: CONFIRM/);
});

test("cli: check requires exactly one target", () => {
  const d = mkdtempSync(join(baseDir, "check-none-"));
  putPolicy(d);
  const r = runCli(["check"], { cwd: d });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /give exactly one of/);
});

test("cli: check --record appends to the audit log", () => {
  const d = mkdtempSync(join(baseDir, "check-record-"));
  putPolicy(d);
  const log = join(d, "audit.jsonl");
  const r = runCli(["check", "--command", "rm -rf /", "--record", "--log", log], { cwd: d });
  assert.equal(r.status, 2);
  const lines = readFileSync(log, "utf8").trim().split("\n");
  assert.equal(lines.length, 1);
  const entry = JSON.parse(lines[0]) as { action: string; source: string };
  assert.equal(entry.action, "deny");
  assert.equal(entry.source, "check");
});

test("cli: hook maps stdin JSON to a decision and logs it", () => {
  const d = mkdtempSync(join(baseDir, "hook-"));
  putPolicy(d);
  const log = join(d, "audit.jsonl");
  const input = JSON.stringify({
    session_id: "s1",
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command: "rm -rf /" },
  });
  const r = runCli(["hook", "--log", log], { cwd: d, input });
  assert.equal(r.status, 0);
  const out = JSON.parse(r.stdout) as { hookSpecificOutput: { permissionDecision: string } };
  assert.equal(out.hookSpecificOutput.permissionDecision, "deny");

  const entries = readFileSync(log, "utf8").trim().split("\n");
  assert.equal(entries.length, 1);
  const entry = JSON.parse(entries[0]) as { source: string; sessionId: string };
  assert.equal(entry.source, "hook");
  assert.equal(entry.sessionId, "s1");
});

test("cli: hook passes through invalid input", () => {
  const d = mkdtempSync(join(baseDir, "hook-bad-"));
  putPolicy(d);
  const r = runCli(["hook"], { cwd: d, input: "{oops" });
  assert.equal(r.status, 0);
  assert.equal(r.stdout, "");
  assert.match(r.stderr, /cannot parse stdin/);
});

test("cli: wrap blocks denied commands without running them", () => {
  const d = mkdtempSync(join(baseDir, "wrap-deny-"));
  putPolicy(d);
  const log = join(d, "audit.jsonl");
  const r = runCli(["wrap", "--log", log, "--", "rm", "-rf", "/"], { cwd: d });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /BLOCKED by rule "deny-rm"/);
  const entry = JSON.parse(readFileSync(log, "utf8").trim()) as { outcome: string };
  assert.equal(entry.outcome, "blocked");
});

test("cli: wrap runs allowed commands and passes the exit code", () => {
  const d = mkdtempSync(join(baseDir, "wrap-run-"));
  putPolicy(d);
  const log = join(d, "audit.jsonl");
  const r = runCli(["wrap", "--log", log, "--", "node", "-p", "42"], { cwd: d });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /42/);
  const entry = JSON.parse(readFileSync(log, "utf8").trim()) as { action: string; outcome: string };
  assert.equal(entry.action, "allow");
  assert.equal(entry.outcome, "executed");
});

test("cli: wrap --dry-run reports without running", () => {
  const d = mkdtempSync(join(baseDir, "wrap-dry-"));
  putPolicy(d);

  const deny = runCli(["wrap", "--dry-run", "--", "rm", "-rf", "/"], { cwd: d });
  assert.equal(deny.status, 2);
  assert.match(deny.stderr, /would DENY/);

  const allow = runCli(["wrap", "--dry-run", "--", "git", "status"], { cwd: d });
  assert.equal(allow.status, 0);
  assert.match(allow.stderr, /would ALLOW/);

  const confirm = runCli(["wrap", "--dry-run", "--", "python", "x"], { cwd: d });
  assert.equal(confirm.status, 3);
  assert.match(confirm.stderr, /would CONFIRM/);
});

test("cli: wrap confirms via --yes and declines without a TTY", () => {
  const d = mkdtempSync(join(baseDir, "wrap-confirm-"));
  writeFileSync(
    join(d, "agentguard.policy.json"),
    JSON.stringify({
      defaults: { command: "deny", file: "allow", network: "confirm" },
      rules: [{ id: "confirm-node", action: "confirm", target: "command", match: { commands: ["node"] } }],
    }),
    "utf8",
  );

  const yes = runCli(["wrap", "--yes", "--", "node", "-p", "7"], { cwd: d });
  assert.equal(yes.status, 0);
  assert.match(yes.stdout, /7/);

  const declined = runCli(["wrap", "--", "node", "-p", "7"], { cwd: d });
  assert.equal(declined.status, 3);
  assert.match(declined.stderr, /not a TTY/);
});

test("cli: log and stats read the audit log", () => {
  const d = mkdtempSync(join(baseDir, "logstats-"));
  putPolicy(d);
  const log = join(d, "audit.jsonl");
  runCli(["check", "--command", "rm -rf /", "--record", "--log", log], { cwd: d });
  runCli(["check", "--command", "git status", "--record", "--log", log], { cwd: d });

  const logText = runCli(["log", "--log", log], { cwd: d });
  assert.equal(logText.status, 0);
  assert.match(logText.stdout, /DENY command rm -rf \/ rule=deny-rm src=check/);
  assert.match(logText.stdout, /ALLOW command git status rule=allow-git src=check/);

  const logJson = runCli(["log", "--log", log, "--json"], { cwd: d });
  const entries = JSON.parse(logJson.stdout) as unknown[];
  assert.equal(entries.length, 2);

  const stats = runCli(["stats", "--log", log], { cwd: d });
  assert.equal(stats.status, 0);
  assert.match(stats.stdout, /total: 2/);
  assert.match(stats.stdout, /deny-rm  1/);

  const statsJson = runCli(["stats", "--log", log, "--json"], { cwd: d });
  const parsed = JSON.parse(statsJson.stdout) as { total: number; byAction: { deny: number } };
  assert.equal(parsed.total, 2);
  assert.equal(parsed.byAction.deny, 1);
});