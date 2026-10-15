import { strict as assert } from "node:assert";
import { test } from "node:test";
import { evaluate, normalizeCommand, splitCompoundCommand } from "../src/engine.js";
import { BUILTIN_DEFAULTS } from "../src/types.js";
import type { Policy, PolicyDefaults, Rule } from "../src/types.js";

function makePolicy(rules: Rule[], defaults?: Partial<PolicyDefaults>): Policy {
  return { rules, defaults: { ...BUILTIN_DEFAULTS, ...defaults } };
}

test("engine: exact mode matches only the full command", () => {
  const policy = makePolicy([
    { id: "exact-npm", action: "allow", target: "command", match: { commands: ["npm test"], mode: "exact" } },
  ]);
  const hit = evaluate(policy, { target: "command", command: "npm test" });
  assert.equal(hit.action, "allow");
  assert.equal(hit.ruleId, "exact-npm");

  const spaced = evaluate(policy, { target: "command", command: "npm  test" });
  assert.equal(spaced.action, "allow");
  assert.equal(spaced.ruleId, "exact-npm");

  const extra = evaluate(policy, { target: "command", command: "npm test --watch" });
  assert.equal(extra.action, "confirm");
  assert.equal(extra.ruleId, null);
});

test("engine: prefix mode respects word boundaries", () => {
  const policy = makePolicy([
    { id: "git-ok", action: "allow", target: "command", match: { commands: ["git"] } },
  ]);
  assert.equal(evaluate(policy, { target: "command", command: "git status" }).action, "allow");
  assert.equal(evaluate(policy, { target: "command", command: "git" }).action, "allow");
  const lookalike = evaluate(policy, { target: "command", command: "gitlab ci" });
  assert.equal(lookalike.action, "confirm");
  assert.equal(lookalike.ruleId, null);
});

test("engine: prefix mode collapses whitespace in command and pattern", () => {
  const policy = makePolicy([
    { id: "npm-test", action: "allow", target: "command", match: { commands: ["npm   test"] } },
  ]);
  const decision = evaluate(policy, { target: "command", command: "npm test" });
  assert.equal(decision.action, "allow");
  assert.equal(decision.ruleId, "npm-test");
});

test("engine: prefix with a trailing non-word character matches freely", () => {
  const policy = makePolicy([
    { id: "rm-root", action: "deny", target: "command", match: { commands: ["rm -rf /"] } },
  ]);
  assert.equal(evaluate(policy, { target: "command", command: "rm -rf /" }).action, "deny");
  assert.equal(evaluate(policy, { target: "command", command: "rm -rf /tmp/x" }).action, "deny");
  assert.equal(evaluate(policy, { target: "command", command: "rm -rf x" }).action, "confirm");
});

test("engine: regex mode searches the whole command", () => {
  const policy = makePolicy([
    {
      id: "rm-guard",
      action: "deny",
      target: "command",
      match: { commands: ["\\brm\\s+-rf\\s+[/~]"], mode: "regex" },
    },
  ]);
  assert.equal(evaluate(policy, { target: "command", command: "sudo rm -rf /" }).action, "deny");
  assert.equal(evaluate(policy, { target: "command", command: "rm -rf ~/data" }).action, "deny");
  const safe = evaluate(policy, { target: "command", command: "rm -rf ./build" });
  assert.equal(safe.action, "confirm");
  assert.equal(safe.ruleId, null);
});

test("engine: file patterns without a slash match the basename", () => {
  const policy = makePolicy([
    { id: "no-pem", action: "deny", target: "file", match: { paths: ["*.pem"] } },
  ], { file: "allow" });
  assert.equal(evaluate(policy, { target: "file", path: "certs/server.pem" }).action, "deny");
  const other = evaluate(policy, { target: "file", path: "certs/server.crt" });
  assert.equal(other.action, "allow");
  assert.equal(other.ruleId, null);
});

test("engine: file patterns with a slash match the full path", () => {
  const policy = makePolicy([
    { id: "secrets", action: "deny", target: "file", match: { paths: ["secrets/**"] } },
  ], { file: "allow" });
  assert.equal(evaluate(policy, { target: "file", path: "secrets/a.json" }).action, "deny");
  const outside = evaluate(policy, { target: "file", path: "app/secrets/a.json" });
  assert.equal(outside.action, "allow");
  assert.equal(outside.ruleId, null);
});

test("engine: file operations filter the match", () => {
  const policy = makePolicy([
    { id: "no-write-src", action: "deny", target: "file", match: { paths: ["src/**"], operations: ["write"] } },
  ], { file: "allow" });
  assert.equal(evaluate(policy, { target: "file", path: "src/a.ts", operation: "write" }).action, "deny");
  const read = evaluate(policy, { target: "file", path: "src/a.ts", operation: "read" });
  assert.equal(read.action, "allow");
  assert.equal(read.ruleId, null);
  const unknown = evaluate(policy, { target: "file", path: "src/a.ts" });
  assert.equal(unknown.action, "allow");
  assert.equal(unknown.ruleId, null);
});

test("engine: file paths with backslashes normalize", () => {
  const policy = makePolicy([
    { id: "src-write", action: "deny", target: "file", match: { paths: ["src/**"] } },
  ], { file: "allow" });
  const decision = evaluate(policy, { target: "file", path: "src\\nested\\x.ts" });
  assert.equal(decision.action, "deny");
});

test("engine: network host globs", () => {
  const policy = makePolicy([
    { id: "no-tracker", action: "deny", target: "network", match: { hosts: ["**.tracker.example"] } },
    { id: "ok-example", action: "allow", target: "network", match: { hosts: ["*.example.com"] } },
  ], { network: "confirm" });

  assert.equal(evaluate(policy, { target: "network", host: "a.tracker.example" }).action, "deny");
  assert.equal(evaluate(policy, { target: "network", host: "tracker.example" }).action, "deny");
  assert.equal(evaluate(policy, { target: "network", host: "api.example.com" }).action, "allow");
  assert.equal(evaluate(policy, { target: "network", host: "API.Example.com" }).action, "allow");
  const deep = evaluate(policy, { target: "network", host: "www.api.example.com" });
  assert.equal(deep.action, "confirm");
  assert.equal(deep.ruleId, null);
});

test("engine: network host ports are ignored for matching", () => {
  const policy = makePolicy([
    { id: "ok-example", action: "allow", target: "network", match: { hosts: ["*.example.com"] } },
  ], { network: "confirm" });
  const decision = evaluate(policy, { target: "network", host: "api.example.com:8443" });
  assert.equal(decision.action, "allow");
  assert.equal(decision.ruleId, "ok-example");
});

test("engine: network host can come from a URL", () => {
  const policy = makePolicy([
    { id: "ok-example", action: "allow", target: "network", match: { hosts: ["*.example.com"] } },
  ], { network: "confirm" });
  const decision = evaluate(policy, { target: "network", url: "https://API.Example.com/path?q=1" });
  assert.equal(decision.action, "allow");
  assert.equal(decision.ruleId, "ok-example");
});

test("engine: first match wins", () => {
  const policy = makePolicy([
    { id: "allow-git", action: "allow", target: "command", match: { commands: ["git"] } },
    { id: "deny-git", action: "deny", target: "command", match: { commands: ["git"] } },
  ]);
  const decision = evaluate(policy, { target: "command", command: "git push" });
  assert.equal(decision.action, "allow");
  assert.equal(decision.ruleId, "allow-git");
});

test("engine: disabled rules are skipped", () => {
  const policy = makePolicy(
    [{ id: "off", action: "deny", target: "command", match: { commands: ["git"] }, disabled: true }],
    { command: "allow" },
  );
  const decision = evaluate(policy, { target: "command", command: "git status" });
  assert.equal(decision.action, "allow");
  assert.equal(decision.ruleId, null);
});

test("engine: the default applies when nothing matches", () => {
  const policy = makePolicy([], { command: "deny" });
  const decision = evaluate(policy, { target: "command", command: "curl http://x" });
  assert.equal(decision.action, "deny");
  assert.equal(decision.ruleId, null);
  assert.match(decision.reason, /default/);
});

test("engine: decision carries the rule reason", () => {
  const policy = makePolicy([
    { id: "r", action: "deny", target: "command", match: { commands: ["curl"] }, reason: "No downloads here." },
  ]);
  assert.equal(evaluate(policy, { target: "command", command: "curl x" }).reason, "No downloads here.");
  const noReason = makePolicy([
    { id: "q", action: "deny", target: "command", match: { commands: ["wget"] } },
  ]);
  assert.equal(evaluate(noReason, { target: "command", command: "wget x" }).reason, 'matched rule "q"');
});

test("engine: compound commands combine with the strictest decision", () => {
  const policy = makePolicy([
    { id: "allow-git", action: "allow", target: "command", match: { commands: ["git"] } },
    { id: "deny-rm", action: "deny", target: "command", match: { commands: ["\\brm\\s+-rf\\s+[/~]"], mode: "regex" } },
  ]);
  const full = "git status && rm -rf /";
  const decision = evaluate(policy, { target: "command", command: full });
  assert.equal(decision.action, "deny");
  assert.equal(decision.ruleId, "deny-rm");
  assert.equal(decision.request.command, full);
});

test("engine: compound commands pass when all segments allow", () => {
  const policy = makePolicy([
    { id: "allow-echo", action: "allow", target: "command", match: { commands: ["echo"] } },
  ]);
  const decision = evaluate(policy, { target: "command", command: "echo a; echo b" });
  assert.equal(decision.action, "allow");
  assert.equal(decision.ruleId, "allow-echo");
});

test("engine: an unmatched segment uses the default strictness", () => {
  const policy = makePolicy([
    { id: "allow-git", action: "allow", target: "command", match: { commands: ["git"] } },
  ], { command: "confirm" });
  const decision = evaluate(policy, { target: "command", command: "git status && curl http://x" });
  assert.equal(decision.action, "confirm");
  assert.equal(decision.ruleId, null);
});

test("engine: malformed requests throw clear errors", () => {
  const policy = makePolicy([]);
  assert.throws(() => evaluate(policy, { target: "command" }), /non-empty command/);
  assert.throws(() => evaluate(policy, { target: "file" }), /non-empty path/);
  assert.throws(() => evaluate(policy, { target: "network" }), /host or a URL/);
  assert.throws(() => evaluate(policy, { target: "network", url: "not a url" }), /invalid URL/);
});

test("engine: helpers splitCompoundCommand and normalizeCommand", () => {
  assert.deepEqual(splitCompoundCommand("a && b || c; d | e\nf"), ["a", "b", "c", "d", "e", "f"]);
  assert.deepEqual(splitCompoundCommand("git status"), ["git status"]);
  assert.equal(normalizeCommand("  npm   run  test "), "npm run test");
});