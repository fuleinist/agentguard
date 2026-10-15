/**
 * Generic command wrapper: agentguard wrap [options] -- <command>
 *
 * allow   -> run the command (child exit code passes through)
 * deny    -> block (exit 2)
 * confirm -> ask once; --yes auto-approves; no TTY declines (exit 3)
 */

import { spawn } from "node:child_process";
import { createInterface } from "node:readline/promises";
import { appendAuditEntry, entryFromDecision, resolveLogPath } from "./audit.js";
import type { AuditOutcome } from "./audit.js";
import { evaluate } from "./engine.js";
import { findPolicyPath, loadPolicy } from "./policy.js";
import type { Decision } from "./types.js";

export interface WrapOptions {
  /** Command parts after "--". */
  command: string[];
  policyPath?: string;
  logPath?: string;
  /** Auto-accept confirm decisions. */
  yes?: boolean;
  /** Evaluate only. Do not run the command. */
  dryRun?: boolean;
  /** TTY override, for tests. */
  isTTY?: boolean;
  /** Confirmation function override, for tests. */
  ask?: (question: string) => Promise<boolean>;
  /** Message sink. Default: stderr. */
  err?: (text: string) => void;
  /** Child stdio. Default: inherit. */
  stdio?: "inherit" | "pipe" | "ignore";
}

export interface WrapResult {
  exitCode: number;
  outcome: "executed" | "blocked" | "declined" | "dry-run" | "error";
}

async function defaultAsk(question: string): Promise<boolean> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    const answer = (await rl.question(question)).trim().toLowerCase();
    return answer === "y" || answer === "yes";
  } finally {
    rl.close();
  }
}

function spawnCommand(commandStr: string, stdio: "inherit" | "pipe" | "ignore", err: (text: string) => void): Promise<number> {
  return new Promise((resolve) => {
    const child = spawn(commandStr, { shell: true, stdio });
    child.on("error", (e) => {
      err(`agentguard wrap: cannot start command: ${e.message}\n`);
      resolve(127);
    });
    child.on("exit", (code, signal) => {
      resolve(typeof code === "number" ? code : signal ? 1 : 0);
    });
  });
}

/** Run one wrapped command through the policy. */
export async function runWrap(opts: WrapOptions): Promise<WrapResult> {
  const err = opts.err ?? ((text: string): void => { process.stderr.write(text); });
  const commandStr = opts.command.join(" ").trim();

  if (commandStr === "") {
    err("agentguard wrap: no command given; usage: agentguard wrap [options] -- <command>\n");
    return { exitCode: 1, outcome: "error" };
  }

  const policyFile = findPolicyPath(opts.policyPath);
  if (policyFile === null) {
    err("agentguard wrap: no policy file found (run `agentguard init` or pass --policy)\n");
    return { exitCode: 1, outcome: "error" };
  }
  const loaded = loadPolicy(policyFile);
  if (!loaded.policy) {
    for (const e of loaded.errors) err(`agentguard wrap: ${e.path}: ${e.message}\n`);
    return { exitCode: 1, outcome: "error" };
  }

  let decision: Decision;
  try {
    decision = evaluate(loaded.policy, { target: "command", command: commandStr });
  } catch (e) {
    err(`agentguard wrap: ${(e as Error).message}\n`);
    return { exitCode: 1, outcome: "error" };
  }

  const log = (outcome: AuditOutcome): void => {
    try {
      appendAuditEntry(resolveLogPath(opts.logPath), entryFromDecision(decision, "wrap", { outcome }));
    } catch (e) {
      err(`agentguard wrap: cannot write audit log: ${(e as Error).message}\n`);
    }
  };

  if (opts.dryRun) {
    log("dry-run");
    err(`agentguard: would ${decision.action.toUpperCase()} "${commandStr}" (rule=${decision.ruleId ?? "-"}: ${decision.reason})\n`);
    const code = decision.action === "allow" ? 0 : decision.action === "deny" ? 2 : 3;
    return { exitCode: code, outcome: "dry-run" };
  }

  if (decision.action === "deny") {
    log("blocked");
    err(`agentguard: BLOCKED by rule "${decision.ruleId ?? "(default)"}": ${decision.reason}\n`);
    return { exitCode: 2, outcome: "blocked" };
  }

  if (decision.action === "confirm") {
    const question = `agentguard: ${decision.reason} Allow "${commandStr}"? [y/N] `;
    let approved = false;
    if (opts.yes) {
      approved = true;
    } else if (opts.ask) {
      approved = await opts.ask(question);
    } else if (opts.isTTY ?? Boolean(process.stdin.isTTY)) {
      approved = await defaultAsk(question);
    } else {
      err("agentguard: confirmation required, but stdin is not a TTY (pass --yes to approve)\n");
      log("declined");
      return { exitCode: 3, outcome: "declined" };
    }
    if (!approved) {
      log("declined");
      err("agentguard: command declined\n");
      return { exitCode: 3, outcome: "declined" };
    }
  }

  log("executed");
  const exitCode = await spawnCommand(commandStr, opts.stdio ?? "inherit", err);
  return { exitCode, outcome: "executed" };
}