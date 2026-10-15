#!/usr/bin/env node
/**
 * agentguard CLI.
 *
 * Commands: init, validate, check, hook, wrap, log, stats, version, help.
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  appendAuditEntry,
  auditStats,
  entryFromDecision,
  filterEntries,
  formatAuditLine,
  parseSince,
  readAuditEntries,
  resolveLogPath,
  sortNewestFirst,
} from "./audit.js";
import { evaluate } from "./engine.js";
import { runHook } from "./hook.js";
import { findPolicyPath, loadPolicy, starterPolicy, summarizePolicy } from "./policy.js";
import { runWrap } from "./wrap.js";
import type { Action, Decision, PolicyRequest, Target } from "./types.js";

type FlagValue = string | boolean;

type ParseResult = { flags: Map<string, FlagValue>; positionals: string[] } | { error: string };

function parseFlags(args: string[], spec: Record<string, "boolean" | "string">): ParseResult {
  const flags = new Map<string, FlagValue>();
  const positionals: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const t = args[i];
    if (t === "--") {
      positionals.push(...args.slice(i + 1));
      break;
    }
    if (t.startsWith("--")) {
      let name = t.slice(2);
      let value: string | undefined;
      const eq = name.indexOf("=");
      if (eq !== -1) {
        value = name.slice(eq + 1);
        name = name.slice(0, eq);
      }
      const kind = spec[name];
      if (!kind) return { error: `unknown flag --${name}` };
      if (kind === "boolean") {
        if (value !== undefined) return { error: `--${name} takes no value` };
        flags.set(name, true);
      } else {
        if (value === undefined) {
          value = args[++i];
          if (value === undefined) return { error: `--${name} needs a value` };
        }
        flags.set(name, value);
      }
    } else {
      positionals.push(t);
    }
  }
  return { flags, positionals };
}

function getStr(flags: Map<string, FlagValue>, name: string): string | undefined {
  const v = flags.get(name);
  return typeof v === "string" ? v : undefined;
}

function getBool(flags: Map<string, FlagValue>, name: string): boolean {
  return flags.get(name) === true;
}

function usageError(message: string): number {
  process.stderr.write(`agentguard: ${message}\n`);
  return 1;
}

function version(): string {
  try {
    const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as {
      version?: string;
    };
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

function printHelp(): void {
  console.log(`agentguard - policy firewall and audit log for coding agents

usage: agentguard <command> [options]

commands:
  init                    write a starter policy (agentguard.policy.json)
  validate                check the policy for errors and warnings
  check                   evaluate one request against the policy
  hook [claude]           run as a Claude Code PreToolUse hook (stdin JSON)
  wrap [options] -- <cmd> run a command through the policy
  log                     show audit entries
  stats                   summarize the audit log
  version                 print the version
  help                    show this text

common options:
  --policy <path>         policy file (default: ./agentguard.policy.json, then ~/.agentguard/policy.json)
  --log <path>            audit log file (default: ~/.agentguard/audit.jsonl)

check options:
  --command <cmd>         evaluate a command
  --file <path>           evaluate a file path
  --operation <kind>      file operation filter: read or write
  --host <host>           evaluate a host
  --url <url>             evaluate a URL
  --json                  print the decision as JSON
  --record                append the decision to the audit log

check exit codes: 0 allow, 2 deny, 3 confirm, 1 error

wrap options:
  --yes                   auto-accept confirm decisions
  --dry-run               evaluate only; do not run the command

hook options:
  --fail-closed           deny when the policy is missing or invalid

log options:
  --action <a>            filter: allow, deny, confirm
  --target <t>            filter: command, file, network
  --rule <id>             filter by rule id
  --since <30m|24h|7d|ISO>  filter by time
  --limit <n>             keep the newest n entries (default 20)
  --json                  print entries as JSON
`);
}

function cmdInit(args: string[]): number {
  const parsed = parseFlags(args, { force: "boolean" });
  if ("error" in parsed) return usageError(parsed.error);
  const file = join(process.cwd(), "agentguard.policy.json");
  if (existsSync(file) && !getBool(parsed.flags, "force")) {
    return usageError("agentguard.policy.json already exists (use --force to overwrite)");
  }
  writeFileSync(file, JSON.stringify(starterPolicy(), null, 2) + "\n", "utf8");
  console.log(`wrote ${file}`);
  console.log("next: agentguard validate   (then wire the hook: agentguard hook claude)");
  return 0;
}

function cmdValidate(args: string[]): number {
  const parsed = parseFlags(args, { policy: "string", json: "boolean" });
  if ("error" in parsed) return usageError(parsed.error);
  const policyFile = findPolicyPath(getStr(parsed.flags, "policy"));
  if (policyFile === null) {
    return usageError("no policy file found (run `agentguard init`)");
  }
  const res = loadPolicy(policyFile);
  if (getBool(parsed.flags, "json")) {
    const summary = res.policy ? summarizePolicy(res.policy) : null;
    console.log(JSON.stringify({ file: policyFile, errors: res.errors, warnings: res.warnings, summary }, null, 2));
  } else {
    console.log(`policy: ${policyFile}`);
    if (res.policy) {
      const s = summarizePolicy(res.policy);
      console.log(`rules: ${s.total} (allow ${s.byAction.allow}, deny ${s.byAction.deny}, confirm ${s.byAction.confirm})`);
      console.log(`targets: command ${s.byTarget.command}, file ${s.byTarget.file}, network ${s.byTarget.network}`);
    }
    for (const w of res.warnings) console.error(`warning: ${w.path}: ${w.message}`);
    for (const e of res.errors) console.error(`error: ${e.path}: ${e.message}`);
    console.log(`result: ${res.errors.length === 0 ? "ok" : "invalid"} (${res.errors.length} errors, ${res.warnings.length} warnings)`);
  }
  return res.errors.length === 0 ? 0 : 1;
}

function cmdCheck(args: string[]): number {
  const parsed = parseFlags(args, {
    policy: "string",
    log: "string",
    record: "boolean",
    command: "string",
    file: "string",
    host: "string",
    url: "string",
    operation: "string",
    json: "boolean",
  });
  if ("error" in parsed) return usageError(parsed.error);
  const flags = parsed.flags;

  const commandStr = getStr(flags, "command");
  const filePath = getStr(flags, "file");
  const host = getStr(flags, "host");
  const url = getStr(flags, "url");
  const operation = getStr(flags, "operation");

  const targetCount =
    (commandStr !== undefined ? 1 : 0) + (filePath !== undefined ? 1 : 0) + (host !== undefined || url !== undefined ? 1 : 0);
  if (targetCount !== 1) {
    return usageError("give exactly one of --command, --file, --host, or --url");
  }

  let request: PolicyRequest;
  if (commandStr !== undefined) {
    request = { target: "command", command: commandStr };
  } else if (filePath !== undefined) {
    if (operation !== undefined && operation !== "read" && operation !== "write") {
      return usageError("operation must be read or write");
    }
    request = { target: "file", path: filePath, ...(operation ? { operation: operation as "read" | "write" } : {}) };
  } else {
    request = { target: "network", ...(host ? { host } : {}), ...(url ? { url } : {}) };
  }

  const policyFile = findPolicyPath(getStr(flags, "policy"));
  if (policyFile === null) {
    return usageError("no policy file found (run `agentguard init`)");
  }
  const loaded = loadPolicy(policyFile);
  if (!loaded.policy) {
    for (const e of loaded.errors) console.error(`error: ${e.path}: ${e.message}`);
    return 1;
  }

  let decision: Decision;
  try {
    decision = evaluate(loaded.policy, request);
  } catch (e) {
    return usageError((e as Error).message);
  }

  if (getBool(flags, "record")) {
    try {
      appendAuditEntry(resolveLogPath(getStr(flags, "log")), entryFromDecision(decision, "check"));
    } catch (e) {
      console.error(`warning: cannot write audit log: ${(e as Error).message}`);
    }
  }

  if (getBool(flags, "json")) {
    console.log(JSON.stringify(decision, null, 2));
  } else {
    console.log(`decision: ${decision.action.toUpperCase()}`);
    console.log(`rule: ${decision.ruleId ?? "(default)"}`);
    console.log(`reason: ${decision.reason}`);
  }
  return decision.action === "allow" ? 0 : decision.action === "deny" ? 2 : 3;
}

function cmdHook(args: string[]): number {
  const parsed = parseFlags(args, { policy: "string", log: "string", "fail-closed": "boolean" });
  if ("error" in parsed) return usageError(parsed.error);
  const sub = parsed.positionals[0];
  if (sub !== undefined && sub !== "claude") {
    return usageError(`unsupported hook host "${sub}" (only: claude)`);
  }
  const result = runHook({
    ...(getStr(parsed.flags, "policy") !== undefined ? { policyPath: getStr(parsed.flags, "policy") } : {}),
    ...(getStr(parsed.flags, "log") !== undefined ? { logPath: getStr(parsed.flags, "log") } : {}),
    failClosed: getBool(parsed.flags, "fail-closed"),
  });
  if (result.stdout) process.stdout.write(result.stdout + "\n");
  return result.exitCode;
}

interface WrapSplit {
  command: string[];
  policy?: string;
  log?: string;
  yes: boolean;
  dryRun: boolean;
}

function splitWrapArgs(args: string[]): WrapSplit | { error: string } {
  const out: WrapSplit = { command: [], yes: false, dryRun: false };
  for (let i = 0; i < args.length; i++) {
    const t = args[i];
    if (t === "--") {
      out.command = args.slice(i + 1);
      return out;
    }
    if (t === "--yes") {
      out.yes = true;
      continue;
    }
    if (t === "--dry-run") {
      out.dryRun = true;
      continue;
    }
    if (t === "--policy" || t.startsWith("--policy=")) {
      const value = t === "--policy" ? args[++i] : t.slice("--policy=".length);
      if (value === undefined) return { error: "--policy needs a value" };
      out.policy = value;
      continue;
    }
    if (t === "--log" || t.startsWith("--log=")) {
      const value = t === "--log" ? args[++i] : t.slice("--log=".length);
      if (value === undefined) return { error: "--log needs a value" };
      out.log = value;
      continue;
    }
    if (t.startsWith("--")) return { error: `unknown flag ${t} (put the command after --)` };
    out.command = args.slice(i);
    return out;
  }
  return out;
}

async function cmdWrap(args: string[]): Promise<number> {
  const split = splitWrapArgs(args);
  if ("error" in split) return usageError(split.error);
  const result = await runWrap({
    command: split.command,
    ...(split.policy !== undefined ? { policyPath: split.policy } : {}),
    ...(split.log !== undefined ? { logPath: split.log } : {}),
    yes: split.yes,
    dryRun: split.dryRun,
  });
  return result.exitCode;
}

function cmdLog(args: string[]): number {
  const parsed = parseFlags(args, {
    log: "string",
    action: "string",
    target: "string",
    rule: "string",
    since: "string",
    limit: "string",
    json: "boolean",
  });
  if ("error" in parsed) return usageError(parsed.error);
  const flags = parsed.flags;

  const actionRaw = getStr(flags, "action");
  if (actionRaw !== undefined && !["allow", "deny", "confirm"].includes(actionRaw)) {
    return usageError("action must be allow, deny, or confirm");
  }
  const targetRaw = getStr(flags, "target");
  if (targetRaw !== undefined && !["command", "file", "network"].includes(targetRaw)) {
    return usageError("target must be command, file, or network");
  }
  let sinceDate: Date | null = null;
  const sinceRaw = getStr(flags, "since");
  if (sinceRaw !== undefined) {
    try {
      sinceDate = parseSince(sinceRaw);
    } catch (e) {
      return usageError((e as Error).message);
    }
  }
  let limit = 20;
  const limitRaw = getStr(flags, "limit");
  if (limitRaw !== undefined) {
    const n = Number(limitRaw);
    if (!Number.isInteger(n) || n < 0) return usageError("limit must be a non-negative integer");
    limit = n;
  }

  const entries = readAuditEntries(resolveLogPath(getStr(flags, "log")));
  const ruleRaw = getStr(flags, "rule");
  const filtered = filterEntries(entries, {
    ...(actionRaw !== undefined ? { action: actionRaw as Action } : {}),
    ...(targetRaw !== undefined ? { target: targetRaw as Target } : {}),
    ...(ruleRaw !== undefined ? { ruleId: ruleRaw } : {}),
    since: sinceDate,
    limit,
  });
  const display = sortNewestFirst(filtered);

  if (getBool(flags, "json")) {
    console.log(JSON.stringify(display, null, 2));
  } else if (display.length === 0) {
    console.log("no entries");
  } else {
    for (const e of display) console.log(formatAuditLine(e));
  }
  return 0;
}

function cmdStats(args: string[]): number {
  const parsed = parseFlags(args, { log: "string", json: "boolean" });
  if ("error" in parsed) return usageError(parsed.error);
  const entries = readAuditEntries(resolveLogPath(getStr(parsed.flags, "log")));
  const stats = auditStats(entries);
  if (getBool(parsed.flags, "json")) {
    console.log(JSON.stringify(stats, null, 2));
  } else {
    console.log(`total: ${stats.total}`);
    console.log(`by action: allow ${stats.byAction.allow}, deny ${stats.byAction.deny}, confirm ${stats.byAction.confirm}`);
    console.log(`by target: command ${stats.byTarget.command}, file ${stats.byTarget.file}, network ${stats.byTarget.network}`);
    console.log("by day:");
    if (stats.byDay.length === 0) console.log("  (none)");
    for (const d of stats.byDay) console.log(`  ${d.day}  ${d.count}`);
    console.log("top denied rules:");
    if (stats.topDeniedRules.length === 0) console.log("  (none)");
    for (const r of stats.topDeniedRules) console.log(`  ${r.ruleId}  ${r.count}`);
  }
  return 0;
}

async function main(argv: string[]): Promise<number> {
  const command = argv[0] ?? "help";
  const args = argv.slice(1);
  switch (command) {
    case "init":
      return cmdInit(args);
    case "validate":
      return cmdValidate(args);
    case "check":
      return cmdCheck(args);
    case "hook":
      return cmdHook(args);
    case "wrap":
      return await cmdWrap(args);
    case "log":
      return cmdLog(args);
    case "stats":
      return cmdStats(args);
    case "version":
    case "--version":
      console.log(`agentguard ${version()}`);
      return 0;
    case "help":
    case "--help":
    case "-h":
      printHelp();
      return 0;
    default:
      process.stderr.write(`agentguard: unknown command "${command}"\n`);
      printHelp();
      return 1;
  }
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (e: unknown) => {
    process.stderr.write(`agentguard: unexpected error: ${(e as Error).message}\n`);
    process.exitCode = 1;
  },
);