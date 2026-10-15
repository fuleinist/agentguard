/**
 * Append-only JSONL audit log.
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { Action, Decision, PolicyRequest, Target } from "./types.js";

export type AuditSource = "hook" | "wrap" | "check";
export type AuditOutcome = "executed" | "declined" | "blocked" | "dry-run";

export interface AuditEntry {
  /** ISO timestamp. */
  ts: string;
  action: Action;
  ruleId: string | null;
  reason: string;
  target: Target;
  request: PolicyRequest;
  source: AuditSource;
  sessionId?: string;
  cwd?: string;
  outcome?: AuditOutcome;
}

/** Default log path: ~/.agentguard/audit.jsonl */
export function defaultLogPath(): string {
  return join(homedir(), ".agentguard", "audit.jsonl");
}

/** Resolve the log path: explicit, then env AGENTGUARD_LOG, then the default. */
export function resolveLogPath(explicit?: string): string {
  if (explicit) return explicit;
  const env = process.env.AGENTGUARD_LOG;
  if (env) return env;
  return defaultLogPath();
}

/** Build an audit entry from a decision. */
export function entryFromDecision(
  decision: Decision,
  source: AuditSource,
  extras: { sessionId?: string; cwd?: string; outcome?: AuditOutcome; ts?: string } = {},
): AuditEntry {
  const entry: AuditEntry = {
    ts: extras.ts ?? new Date().toISOString(),
    action: decision.action,
    ruleId: decision.ruleId,
    reason: decision.reason,
    target: decision.request.target,
    request: decision.request,
    source,
  };
  if (extras.sessionId) entry.sessionId = extras.sessionId;
  if (extras.cwd) entry.cwd = extras.cwd;
  if (extras.outcome) entry.outcome = extras.outcome;
  return entry;
}

/** Append one entry as a JSON line. Creates the directory when needed. */
export function appendAuditEntry(file: string, entry: AuditEntry): void {
  mkdirSync(dirname(file), { recursive: true });
  appendFileSync(file, JSON.stringify(entry) + "\n", "utf8");
}

/** Read all entries. Corrupt lines are skipped. Missing file reads as empty. */
export function readAuditEntries(file: string): AuditEntry[] {
  if (!existsSync(file)) return [];
  const text = readFileSync(file, "utf8");
  const entries: AuditEntry[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (trimmed === "") continue;
    try {
      entries.push(JSON.parse(trimmed) as AuditEntry);
    } catch {
      // Skip corrupt lines.
    }
  }
  return entries;
}

/** Parse a --since value: "30m", "24h", "7d", "all", or an ISO date. */
export function parseSince(input: string, now: Date = new Date()): Date | null {
  const s = input.trim().toLowerCase();
  if (s === "" || s === "all") return null;
  const m = /^(\d+)(m|h|d)$/.exec(s);
  if (m) {
    const n = Number(m[1]);
    const unit = m[2];
    const ms = n * (unit === "m" ? 60_000 : unit === "h" ? 3_600_000 : 86_400_000);
    return new Date(now.getTime() - ms);
  }
  const d = new Date(input);
  if (!Number.isNaN(d.getTime())) return d;
  throw new Error(`invalid since value: ${input} (use 30m, 24h, 7d, or an ISO date)`);
}

export interface AuditFilter {
  action?: Action;
  target?: Target;
  ruleId?: string;
  since?: Date | null;
  limit?: number;
}

/** Filter entries in file order. `limit` keeps the newest N.
 */
export function filterEntries(entries: AuditEntry[], filter: AuditFilter = {}): AuditEntry[] {
  let out = entries.filter((e) => {
    if (filter.action && e.action !== filter.action) return false;
    if (filter.target && e.target !== filter.target) return false;
    if (filter.ruleId && e.ruleId !== filter.ruleId) return false;
    if (filter.since && new Date(e.ts).getTime() < filter.since.getTime()) return false;
    return true;
  });
  if (filter.limit !== undefined && filter.limit >= 0 && out.length > filter.limit) {
    out = out.slice(out.length - filter.limit);
  }
  return out;
}

export interface AuditStats {
  total: number;
  byAction: Record<Action, number>;
  byTarget: Record<Target, number>;
  byDay: { day: string; count: number }[];
  topDeniedRules: { ruleId: string; count: number }[];
}

/** Count entries by action, target, day, and the top denied rules. */
export function auditStats(entries: AuditEntry[]): AuditStats {
  const byAction: Record<Action, number> = { allow: 0, deny: 0, confirm: 0 };
  const byTarget: Record<Target, number> = { command: 0, file: 0, network: 0 };
  const days = new Map<string, number>();
  const denied = new Map<string, number>();
  for (const e of entries) {
    byAction[e.action]++;
    byTarget[e.target]++;
    const day = e.ts.slice(0, 10);
    days.set(day, (days.get(day) ?? 0) + 1);
    if (e.action === "deny") {
      const key = e.ruleId ?? "(default)";
      denied.set(key, (denied.get(key) ?? 0) + 1);
    }
  }
  const byDay = [...days.entries()]
    .map(([day, count]) => ({ day, count }))
    .sort((a, b) => (a.day < b.day ? -1 : 1))
    .slice(-7);
  const topDeniedRules = [...denied.entries()]
    .map(([ruleId, count]) => ({ ruleId, count }))
    .sort((a, b) => b.count - a.count || (a.ruleId < b.ruleId ? -1 : 1))
    .slice(0, 5);
  return { total: entries.length, byAction, byTarget, byDay, topDeniedRules };
}

/** One-line summary of the request part. */
export function summarizeRequest(request: PolicyRequest): string {
  if (request.target === "command") return request.command ?? "";
  if (request.target === "file") return request.path ?? "";
  return request.host ?? request.url ?? "";
}

/** One-line text form for the `log` command. */
export function formatAuditLine(e: AuditEntry): string {
  const rule = e.ruleId ?? "-";
  const outcome = e.outcome ? ` outcome=${e.outcome}` : "";
  return `${e.ts} ${e.action.toUpperCase()} ${e.target} ${summarizeRequest(e.request)} rule=${rule} src=${e.source}${outcome}`;
}