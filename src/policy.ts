/**
 * Policy loading, validation, and helpers.
 */

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { BUILTIN_DEFAULTS } from "./types.js";
import type {
  Action,
  CommandMatch,
  FileMatch,
  FileOperation,
  NetworkMatch,
  Policy,
  PolicyDefaults,
  Rule,
  Target,
} from "./types.js";

const ACTIONS: readonly Action[] = ["allow", "deny", "confirm"];
const TARGETS: readonly Target[] = ["command", "file", "network"];

export interface PolicyIssue {
  /** JSON path of the problem, for example "rules[2].action". */
  path: string;
  message: string;
}

export interface ValidationResult {
  /** Normalized policy. null when errors exist. */
  policy: Policy | null;
  errors: PolicyIssue[];
  warnings: PolicyIssue[];
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.trim() !== "";
}

function sameStringArray(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

function sameMatch(a: Rule, b: Rule): boolean {
  if (a.target !== b.target) return false;
  if (a.target === "command") {
    const am = a.match as CommandMatch;
    const bm = b.match as CommandMatch;
    return (am.mode ?? "prefix") === (bm.mode ?? "prefix") && sameStringArray(am.commands, bm.commands);
  }
  if (a.target === "file") {
    const am = a.match as FileMatch;
    const bm = b.match as FileMatch;
    return sameStringArray(am.paths, bm.paths) && sameStringArray(am.operations ?? [], bm.operations ?? []);
  }
  const am = a.match as NetworkMatch;
  const bm = b.match as NetworkMatch;
  return sameStringArray(am.hosts, bm.hosts);
}

function validateMatch(
  target: Target,
  m: Record<string, unknown>,
  path: string,
  errors: PolicyIssue[],
  warnings: PolicyIssue[],
): CommandMatch | FileMatch | NetworkMatch | null {
  if (target === "command") {
    if (!Array.isArray(m.commands) || m.commands.length === 0 || !m.commands.every(isNonEmptyString)) {
      errors.push({ path: `${path}.commands`, message: "commands must be a non-empty array of strings" });
      return null;
    }
    const commands = m.commands as string[];
    const mode = m.mode;
    if (mode !== undefined && (typeof mode !== "string" || !["exact", "prefix", "regex"].includes(mode))) {
      errors.push({ path: `${path}.mode`, message: "mode must be one of exact, prefix, regex" });
      return null;
    }
    if (mode === "regex") {
      for (const c of commands) {
        try {
          new RegExp(c);
        } catch (e) {
          errors.push({ path: `${path}.commands`, message: `invalid regex "${c}": ${(e as Error).message}` });
          return null;
        }
      }
    }
    for (const k of Object.keys(m)) {
      if (!["commands", "mode"].includes(k)) warnings.push({ path: `${path}.${k}`, message: `unknown match key "${k}"` });
    }
    return mode === undefined ? { commands } : { commands, mode: mode as "exact" | "prefix" | "regex" };
  }

  if (target === "file") {
    if (!Array.isArray(m.paths) || m.paths.length === 0 || !m.paths.every(isNonEmptyString)) {
      errors.push({ path: `${path}.paths`, message: "paths must be a non-empty array of strings" });
      return null;
    }
    const paths = m.paths as string[];
    let operations: FileMatch["operations"];
    if (m.operations !== undefined) {
      if (!Array.isArray(m.operations) || !m.operations.every((o) => o === "read" || o === "write")) {
        errors.push({ path: `${path}.operations`, message: 'operations entries must be "read" or "write"' });
        return null;
      }
      operations = m.operations as FileOperation[];
      if (operations.length === 0) {
        warnings.push({ path: `${path}.operations`, message: "operations is empty; the rule can never match" });
      }
    }
    for (const k of Object.keys(m)) {
      if (!["paths", "operations"].includes(k)) warnings.push({ path: `${path}.${k}`, message: `unknown match key "${k}"` });
    }
    return operations === undefined ? { paths } : { paths, operations };
  }

  if (!Array.isArray(m.hosts) || m.hosts.length === 0 || !m.hosts.every(isNonEmptyString)) {
    errors.push({ path: `${path}.hosts`, message: "hosts must be a non-empty array of strings" });
    return null;
  }
  for (const k of Object.keys(m)) {
    if (!["hosts"].includes(k)) warnings.push({ path: `${path}.${k}`, message: `unknown match key "${k}"` });
  }
  return { hosts: m.hosts as string[] };
}

/** Validate unknown data and return a normalized policy or errors. */
export function validatePolicy(raw: unknown): ValidationResult {
  const errors: PolicyIssue[] = [];
  const warnings: PolicyIssue[] = [];

  if (!isPlainObject(raw)) {
    errors.push({ path: "", message: "policy must be a JSON object" });
    return { policy: null, errors, warnings };
  }

  const knownTop = ["$schema", "name", "rules", "defaults"];
  for (const k of Object.keys(raw)) {
    if (!knownTop.includes(k)) warnings.push({ path: k, message: `unknown top-level key "${k}"` });
  }

  // defaults
  const defaults: PolicyDefaults = { ...BUILTIN_DEFAULTS };
  if (raw.defaults === undefined) {
    warnings.push({
      path: "defaults",
      message: "no defaults defined; using built-in defaults (command=confirm, file=allow, network=confirm)",
    });
  } else if (!isPlainObject(raw.defaults)) {
    errors.push({ path: "defaults", message: "defaults must be an object" });
  } else {
    for (const key of ["command", "file", "network"] as const) {
      const v = raw.defaults[key];
      if (v === undefined) continue;
      if (typeof v === "string" && (ACTIONS as readonly string[]).includes(v)) {
        defaults[key] = v as Action;
      } else {
        errors.push({ path: `defaults.${key}`, message: `${key} must be one of allow, deny, confirm` });
      }
    }
    for (const k of Object.keys(raw.defaults)) {
      if (!["command", "file", "network"].includes(k)) {
        warnings.push({ path: `defaults.${k}`, message: `unknown defaults key "${k}"` });
      }
    }
  }

  // rules
  const rules: Rule[] = [];
  let rawRules: unknown = raw.rules;
  if (rawRules === undefined) {
    warnings.push({ path: "rules", message: "no rules defined" });
    rawRules = [];
  }
  if (!Array.isArray(rawRules)) {
    errors.push({ path: "rules", message: "rules must be an array" });
  } else {
    const seenIds = new Set<string>();
    rawRules.forEach((rr, i) => {
      const rp = `rules[${i}]`;
      if (!isPlainObject(rr)) {
        errors.push({ path: rp, message: "rule must be an object" });
        return;
      }

      let id: string;
      if (rr.id === undefined) {
        id = `rule-${i}`;
        warnings.push({ path: `${rp}.id`, message: `rule has no id; using "${id}"` });
      } else if (isNonEmptyString(rr.id)) {
        id = rr.id;
      } else {
        errors.push({ path: `${rp}.id`, message: "id must be a non-empty string" });
        id = `rule-${i}`;
      }
      if (seenIds.has(id)) {
        errors.push({ path: `${rp}.id`, message: `duplicate rule id "${id}"` });
      }
      seenIds.add(id);

      let action: Action | null = null;
      if (typeof rr.action === "string" && (ACTIONS as readonly string[]).includes(rr.action)) {
        action = rr.action as Action;
      } else {
        errors.push({ path: `${rp}.action`, message: "action must be one of allow, deny, confirm" });
      }

      let target: Target | null = null;
      if (typeof rr.target === "string" && (TARGETS as readonly string[]).includes(rr.target)) {
        target = rr.target as Target;
      } else {
        errors.push({ path: `${rp}.target`, message: "target must be one of command, file, network" });
      }

      let match: CommandMatch | FileMatch | NetworkMatch | null = null;
      if (rr.match === undefined) {
        errors.push({ path: `${rp}.match`, message: "match is required" });
      } else if (!isPlainObject(rr.match)) {
        errors.push({ path: `${rp}.match`, message: "match must be an object" });
      } else if (target !== null) {
        match = validateMatch(target, rr.match, `${rp}.match`, errors, warnings);
      }

      if (rr.reason !== undefined && typeof rr.reason !== "string") {
        warnings.push({ path: `${rp}.reason`, message: "reason should be a string" });
      }
      if (rr.disabled !== undefined && typeof rr.disabled !== "boolean") {
        warnings.push({ path: `${rp}.disabled`, message: "disabled should be a boolean" });
      }
      for (const k of Object.keys(rr)) {
        if (!["id", "action", "target", "match", "reason", "disabled"].includes(k)) {
          warnings.push({ path: `${rp}.${k}`, message: `unknown rule key "${k}"` });
        }
      }

      if (action !== null && target !== null && match !== null) {
        const rule: Rule = { id, action, target, match };
        if (typeof rr.reason === "string") rule.reason = rr.reason;
        if (rr.disabled === true) rule.disabled = true;
        rules.push(rule);
      }
    });

    // Warn when a rule repeats an earlier match and can never fire.
    for (let i = 0; i < rules.length; i++) {
      for (let j = 0; j < i; j++) {
        const a = rules[i];
        const b = rules[j];
        if (!a.disabled && !b.disabled && sameMatch(a, b)) {
          warnings.push({
            path: `rules[${i}]`,
            message: `rule "${a.id}" repeats the match of earlier rule "${b.id}"; it can never fire`,
          });
          break;
        }
      }
    }
  }

  if (errors.length > 0) {
    return { policy: null, errors, warnings };
  }
  const policy: Policy = { rules, defaults };
  if (typeof raw.$schema === "string") policy.$schema = raw.$schema;
  if (typeof raw.name === "string") policy.name = raw.name;
  return { policy, errors, warnings };
}

/** Read a policy file and validate it. Handles a UTF-8 BOM. */
export function loadPolicy(file: string): ValidationResult {
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch {
    return { policy: null, errors: [{ path: file, message: `cannot read policy file: ${file}` }], warnings: [] };
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text.replace(/^\uFEFF/, ""));
  } catch (e) {
    return { policy: null, errors: [{ path: file, message: `invalid JSON: ${(e as Error).message}` }], warnings: [] };
  }
  return validatePolicy(raw);
}

/** Find the policy file: explicit path, env var, cwd, then home. */
export function findPolicyPath(explicit?: string): string | null {
  if (explicit) return explicit;
  const env = process.env.AGENTGUARD_POLICY;
  if (env) return env;
  const cwdPath = join(process.cwd(), "agentguard.policy.json");
  if (existsSync(cwdPath)) return cwdPath;
  const homePath = join(homedir(), ".agentguard", "policy.json");
  if (existsSync(homePath)) return homePath;
  return null;
}

/** The starter policy written by `agentguard init`. */
export function starterPolicy(): Policy {
  return {
    name: "agentguard starter policy",
    defaults: { command: "confirm", file: "allow", network: "confirm" },
    rules: [
      {
        id: "deny-secrets",
        action: "deny",
        target: "file",
        match: {
          paths: ["**/.env", "**/.env.*", "**/*.pem", "**/*.key", "**/.ssh/**", "**/.aws/**"],
        },
        reason: "Credential files are off limits.",
      },
      {
        id: "deny-destructive-rm",
        action: "deny",
        target: "command",
        match: {
          commands: ["\\brm\\s+-rf\\s+[/~]", "\\brm\\s+-fr\\s+[/~]"],
          mode: "regex",
        },
        reason: "Recursive delete of root or home is blocked.",
      },
      {
        id: "deny-dangerous",
        action: "deny",
        target: "command",
        match: {
          commands: ["mkfs", "dd if=", "diskpart", "shutdown", "reboot"],
          mode: "prefix",
        },
        reason: "Disk and system commands are blocked.",
      },
      {
        id: "confirm-sudo",
        action: "confirm",
        target: "command",
        match: { commands: ["\\bsudo\\b"], mode: "regex" },
        reason: "Elevated commands need a checkpoint.",
      },
      {
        id: "allow-dev-tools",
        action: "allow",
        target: "command",
        match: {
          commands: ["git", "npm", "pnpm", "yarn", "node", "python", "pip", "gh", "rg", "grep", "ls", "cat", "head", "tail"],
        },
        reason: "Common development tools are allowed.",
      },
      {
        id: "allow-local-net",
        action: "allow",
        target: "network",
        match: { hosts: ["localhost", "127.0.0.1", "::1"] },
        reason: "Local services are allowed.",
      },
    ],
  };
}

export interface PolicySummary {
  total: number;
  enabled: number;
  byAction: Record<Action, number>;
  byTarget: Record<Target, number>;
}

/** Count rules for the `validate` summary output. Disabled rules stay out of the counts. */
export function summarizePolicy(policy: Policy): PolicySummary {
  const byAction: Record<Action, number> = { allow: 0, deny: 0, confirm: 0 };
  const byTarget: Record<Target, number> = { command: 0, file: 0, network: 0 };
  let enabled = 0;
  for (const rule of policy.rules) {
    if (rule.disabled) continue;
    enabled++;
    byAction[rule.action]++;
    byTarget[rule.target]++;
  }
  return { total: policy.rules.length, enabled, byAction, byTarget };
}