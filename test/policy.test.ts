import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  findPolicyPath,
  loadPolicy,
  starterPolicy,
  summarizePolicy,
  validatePolicy,
} from "../src/policy.js";
import { BUILTIN_DEFAULTS } from "../src/types.js";

const dir = mkdtempSync(join(tmpdir(), "agentguard-policy-"));

function validPolicyJson(): unknown {
  return {
    name: "test policy",
    defaults: { command: "confirm", file: "allow", network: "confirm" },
    rules: [
      { id: "r1", action: "allow", target: "command", match: { commands: ["git"], mode: "prefix" } },
    ],
  };
}

test("policy: valid policy passes with no errors", () => {
  const result = validatePolicy(validPolicyJson());
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.warnings, []);
  assert.notEqual(result.policy, null);
  assert.equal(result.policy!.rules.length, 1);
  assert.equal(result.policy!.rules[0].id, "r1");
});

test("policy: missing id gets a generated id and a warning", () => {
  const raw = validPolicyJson() as { rules: unknown[] };
  raw.rules = [{ action: "allow", target: "command", match: { commands: ["git"] } }];
  const result = validatePolicy(raw);
  assert.deepEqual(result.errors, []);
  assert.ok(result.warnings.some((w) => w.path === "rules[0].id"));
  assert.equal(result.policy!.rules[0].id, "rule-0");
});

test("policy: missing defaults warns and fills built-ins", () => {
  const raw = validPolicyJson() as Record<string, unknown>;
  delete raw.defaults;
  const result = validatePolicy(raw);
  assert.deepEqual(result.errors, []);
  assert.ok(result.warnings.some((w) => w.path === "defaults" && /built-in defaults/.test(w.message)));
  assert.deepEqual(result.policy!.defaults, BUILTIN_DEFAULTS);
});

test("policy: invalid default action is an error; partial defaults get filled", () => {
  const bad = validatePolicy({
    defaults: { command: "yolo" },
    rules: [{ id: "a", action: "allow", target: "command", match: { commands: ["git"] } }],
  });
  assert.ok(bad.errors.some((e) => e.path === "defaults.command"));
  assert.equal(bad.policy, null);

  const partial = validatePolicy({
    defaults: { file: "deny" },
    rules: [{ id: "a", action: "deny", target: "file", match: { paths: ["**/.env"] } }],
  });
  assert.deepEqual(partial.errors, []);
  assert.equal(partial.policy!.defaults.file, "deny");
  assert.equal(partial.policy!.defaults.command, "confirm");
});

test("policy: rules must be an array", () => {
  const result = validatePolicy({ rules: { nope: true }, defaults: { command: "allow", file: "allow", network: "allow" } });
  assert.ok(result.errors.some((e) => e.path === "rules" && /array/.test(e.message)));
  assert.equal(result.policy, null);
});

test("policy: bad action and target produce errors", () => {
  const result = validatePolicy({
    rules: [
      { id: "a", action: "maybe", target: "command", match: { commands: ["git"] } },
      { id: "b", action: "allow", target: "disk", match: { commands: ["git"] } },
    ],
  });
  assert.ok(result.errors.some((e) => e.path === "rules[0].action"));
  assert.ok(result.errors.some((e) => e.path === "rules[1].target"));
});

test("policy: command match requires a non-empty string list and a valid mode", () => {
  const empty = validatePolicy({ rules: [{ id: "a", action: "allow", target: "command", match: { commands: [] } }] });
  assert.ok(empty.errors.some((e) => e.path === "rules[0].match.commands"));

  const blank = validatePolicy({ rules: [{ id: "a", action: "allow", target: "command", match: { commands: [""] } }] });
  assert.ok(blank.errors.some((e) => e.path === "rules[0].match.commands"));

  const badMode = validatePolicy({
    rules: [{ id: "a", action: "allow", target: "command", match: { commands: ["git"], mode: "fuzzy" } }],
  });
  assert.ok(badMode.errors.some((e) => e.path === "rules[0].match.mode"));

  const missing = validatePolicy({ rules: [{ id: "a", action: "allow", target: "command" }] });
  assert.ok(missing.errors.some((e) => /match is required/.test(e.message)));
});

test("policy: invalid regex is an error", () => {
  const result = validatePolicy({
    rules: [{ id: "a", action: "deny", target: "command", match: { commands: ["("], mode: "regex" } }],
  });
  assert.ok(result.errors.some((e) => /invalid regex/.test(e.message)));
});

test("policy: duplicate rule ids are errors", () => {
  const result = validatePolicy({
    rules: [
      { id: "dup", action: "allow", target: "command", match: { commands: ["git"] } },
      { id: "dup", action: "deny", target: "command", match: { commands: ["curl"] } },
    ],
  });
  assert.ok(result.errors.some((e) => e.path === "rules[1].id" && /duplicate/.test(e.message)));
});

test("policy: file operations are validated", () => {
  const bad = validatePolicy({
    rules: [{ id: "a", action: "deny", target: "file", match: { paths: ["src/**"], operations: ["read", "exec"] } }],
  });
  assert.ok(bad.errors.some((e) => e.path === "rules[0].match.operations"));

  const good = validatePolicy({
    rules: [{ id: "a", action: "deny", target: "file", match: { paths: ["src/**"], operations: ["read"] } }],
  });
  assert.deepEqual(good.errors, []);

  const empty = validatePolicy({
    rules: [{ id: "a", action: "deny", target: "file", match: { paths: ["src/**"], operations: [] } }],
  });
  assert.ok(empty.warnings.some((w) => /can never match/.test(w.message)));
});

test("policy: unknown keys become warnings", () => {
  const raw = validPolicyJson() as Record<string, unknown>;
  raw.extra = 1;
  (raw.rules as Array<Record<string, unknown>>)[0].when = {};
  ((raw.rules as Array<Record<string, unknown>>)[0].match as Record<string, unknown>).glob = [];
  const result = validatePolicy(raw);
  assert.deepEqual(result.errors, []);
  assert.ok(result.warnings.some((w) => w.path === "extra"));
  assert.ok(result.warnings.some((w) => w.path === "rules[0].when"));
  assert.ok(result.warnings.some((w) => w.path === "rules[0].match.glob"));
});

test("policy: a repeated match warns that the later rule can never fire", () => {
  const result = validatePolicy({
    rules: [
      { id: "a", action: "allow", target: "command", match: { commands: ["git"] } },
      { id: "b", action: "allow", target: "command", match: { commands: ["git"] } },
    ],
  });
  assert.ok(result.warnings.some((w) => w.path === "rules[1]" && /can never fire/.test(w.message)));
});

test("policy: disabled rules stay but are not counted in the summary", () => {
  const policy = {
    rules: [
      { id: "a", action: "deny" as const, target: "command" as const, match: { commands: ["git"] }, disabled: true },
      { id: "b", action: "allow" as const, target: "command" as const, match: { commands: ["npm"] } },
    ],
    defaults: { ...BUILTIN_DEFAULTS },
  };
  const summary = summarizePolicy(policy);
  assert.equal(summary.total, 2);
  assert.equal(summary.enabled, 1);
  assert.equal(summary.byAction.allow, 1);
  assert.equal(summary.byAction.deny, 0);
});

test("policy: loadPolicy reports missing files and bad JSON", () => {
  const missing = loadPolicy(join(dir, "missing.json"));
  assert.ok(missing.errors[0] && /cannot read policy file/.test(missing.errors[0].message));

  const badPath = join(dir, "bad.json");
  writeFileSync(badPath, "{ not json", "utf8");
  const bad = loadPolicy(badPath);
  assert.ok(bad.errors[0] && /invalid JSON/.test(bad.errors[0].message));
});

test("policy: loadPolicy accepts a UTF-8 BOM", () => {
  const bomPath = join(dir, "bom.json");
  writeFileSync(bomPath, "\uFEFF" + JSON.stringify(validPolicyJson()), "utf8");
  const result = loadPolicy(bomPath);
  assert.deepEqual(result.errors, []);
  assert.notEqual(result.policy, null);
});

test("policy: starter policy validates cleanly and summarizes", () => {
  const result = validatePolicy(starterPolicy());
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.warnings, []);
  const summary = summarizePolicy(result.policy!);
  assert.equal(summary.total, 6);
  assert.equal(summary.enabled, 6);
  assert.deepEqual(summary.byAction, { allow: 2, deny: 3, confirm: 1 });
  assert.deepEqual(summary.byTarget, { command: 4, file: 1, network: 1 });
});

test("policy: findPolicyPath returns an explicit path unchanged", () => {
  assert.equal(findPolicyPath("./custom.policy.json"), "./custom.policy.json");
});