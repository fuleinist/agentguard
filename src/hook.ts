/**
 * Claude Code PreToolUse hook adapter.
 *
 * Reads the hook payload from stdin. Evaluates it against the policy.
 * Writes one JSON decision to stdout. Appends one audit line.
 */

import { readFileSync } from "node:fs";
import { appendAuditEntry, entryFromDecision, resolveLogPath } from "./audit.js";
import { evaluate } from "./engine.js";
import { findPolicyPath, loadPolicy } from "./policy.js";
import type { Decision, PolicyRequest } from "./types.js";

export interface ClaudeHookInput {
  session_id?: string;
  transcript_path?: string;
  cwd?: string;
  hook_event_name?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
}

function firstString(...vals: unknown[]): string | null {
  for (const v of vals) {
    if (typeof v === "string" && v.trim() !== "") return v;
  }
  return null;
}

/** Map a Claude Code tool call to a policy request. Unmapped tools return null. */
export function mapClaudeTool(input: ClaudeHookInput): PolicyRequest | null {
  const tool = input.tool_name ?? "";
  const ti =
    typeof input.tool_input === "object" && input.tool_input !== null ? input.tool_input : {};

  switch (tool) {
    case "Bash": {
      const command = typeof ti.command === "string" ? ti.command : "";
      if (command.trim() === "") return null;
      return { target: "command", command, ...(input.cwd ? { cwd: input.cwd } : {}) };
    }
    case "Read": {
      const p = firstString(ti.file_path, ti.path);
      return p ? { target: "file", path: p, operation: "read", ...(input.cwd ? { cwd: input.cwd } : {}) } : null;
    }
    case "Write":
    case "Edit":
    case "MultiEdit":
    case "NotebookEdit": {
      const p = firstString(ti.file_path, ti.notebook_path, ti.path);
      return p ? { target: "file", path: p, operation: "write", ...(input.cwd ? { cwd: input.cwd } : {}) } : null;
    }
    case "WebFetch": {
      const url = typeof ti.url === "string" ? ti.url : "";
      if (url.trim() === "") return null;
      return { target: "network", url, ...(input.cwd ? { cwd: input.cwd } : {}) };
    }
    default:
      return null;
  }
}

export interface ClaudeHookOutput {
  hookSpecificOutput: {
    hookEventName: "PreToolUse";
    permissionDecision: "allow" | "deny" | "ask";
    permissionDecisionReason: string;
  };
}

/** Convert a decision to the hook JSON shape. "confirm" becomes "ask". */
export function decisionToHookOutput(decision: Decision): ClaudeHookOutput {
  const permissionDecision = decision.action === "confirm" ? "ask" : decision.action;
  return {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision,
      permissionDecisionReason: decision.reason,
    },
  };
}

function denyOutput(reason: string): ClaudeHookOutput {
  return {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: reason,
    },
  };
}

export interface RunHookOptions {
  policyPath?: string;
  logPath?: string;
  /** When true, deny if the policy is missing or invalid. */
  failClosed?: boolean;
  /** Override stdin, for tests. Default: read fd 0. */
  stdinText?: string;
  /** Warning sink, for tests. Default: stderr. */
  stderr?: (line: string) => void;
}

export interface RunHookResult {
  exitCode: number;
  /** JSON output string, or "" for no opinion. */
  stdout: string;
  logged: boolean;
}

function readStdin(): string {
  try {
    return readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

/** Run the hook: stdin JSON in, decision JSON out. Never throws. */
export function runHook(options: RunHookOptions = {}): RunHookResult {
  const warn = options.stderr ?? ((line: string) => process.stderr.write(line + "\n"));
  const raw = options.stdinText ?? readStdin();

  let input: ClaudeHookInput;
  try {
    input = JSON.parse(raw.replace(/^\uFEFF/, "")) as ClaudeHookInput;
  } catch {
    warn("agentguard hook: cannot parse stdin as JSON; passing through");
    return { exitCode: 0, stdout: "", logged: false };
  }

  const request = mapClaudeTool(input);
  if (request === null) return { exitCode: 0, stdout: "", logged: false };

  const policyPath = findPolicyPath(options.policyPath);
  if (!policyPath) {
    warn("agentguard hook: no policy file found; passing through");
    if (options.failClosed) {
      return { exitCode: 0, stdout: JSON.stringify(denyOutput("agentguard: no policy file found")), logged: false };
    }
    return { exitCode: 0, stdout: "", logged: false };
  }

  const result = loadPolicy(policyPath);
  if (!result.policy) {
    for (const err of result.errors) warn(`agentguard hook: ${err.path}: ${err.message}`);
    if (options.failClosed) {
      return { exitCode: 0, stdout: JSON.stringify(denyOutput("agentguard: policy file is missing or invalid")), logged: false };
    }
    warn("agentguard hook: passing through");
    return { exitCode: 0, stdout: "", logged: false };
  }

  let decision: Decision;
  try {
    decision = evaluate(result.policy, request);
  } catch (e) {
    warn(`agentguard hook: ${(e as Error).message}; passing through`);
    return { exitCode: 0, stdout: "", logged: false };
  }

  let logged = false;
  try {
    appendAuditEntry(
      resolveLogPath(options.logPath),
      entryFromDecision(decision, "hook", {
        ...(input.session_id ? { sessionId: input.session_id } : {}),
        ...(input.cwd ? { cwd: input.cwd } : {}),
      }),
    );
    logged = true;
  } catch (e) {
    warn(`agentguard hook: cannot write audit log: ${(e as Error).message}`);
  }

  return { exitCode: 0, stdout: JSON.stringify(decisionToHookOutput(decision)), logged };
}