import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  appendAuditEntry,
  auditStats,
  defaultLogPath,
  entryFromDecision,
  filterEntries,
  formatAuditLine,
  parseSince,
  readAuditEntries,
  resolveLogPath,
  sortNewestFirst,
  summarizeRequest,
} from "../src/audit.js";
import type { AuditEntry } from "../src/audit.js";
import type { Decision } from "../src/types.js";

const dir = mkdtempSync(join(tmpdir(), "agentguard-audit-"));

function sampleEntry(over: Partial<AuditEntry> = {}): AuditEntry {
  return {
    ts: "2026-10-16T00:00:00.000Z",
    action: "allow",
    ruleId: null,
    reason: "test",
    target: "command",
    request: { target: "command", command: "git status" },
    source: "check",
    ...over,
  };
}

test("audit: append and read round trip", () => {
  const file = join(dir, "roundtrip.jsonl");
  appendAuditEntry(file, sampleEntry());
  appendAuditEntry(file, sampleEntry({ action: "deny", ruleId: "r1" }));
  const entries = readAuditEntries(file);
  assert.equal(entries.length, 2);
  assert.deepEqual(entries[0], sampleEntry());
  assert.equal(entries[1].action, "deny");
  assert.equal(entries[1].ruleId, "r1");
});

test("audit: missing file reads as empty; corrupt lines are skipped", () => {
  assert.deepEqual(readAuditEntries(join(dir, "missing.jsonl")), []);
  const file = join(dir, "corrupt.jsonl");
  writeFileSync(file, "not json\n" + JSON.stringify(sampleEntry()) + "\n\n", "utf8");
  const entries = readAuditEntries(file);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].reason, "test");
});

test("audit: entryFromDecision fills fields and keeps extras optional", () => {
  const decision: Decision = {
    action: "deny",
    ruleId: "deny-rm",
    reason: "blocked",
    request: { target: "command", command: "rm -rf /" },
  };
  const entry = entryFromDecision(decision, "wrap", {
    sessionId: "s1",
    outcome: "blocked",
    ts: "2026-10-16T00:00:00.000Z",
  });
  assert.equal(entry.ts, "2026-10-16T00:00:00.000Z");
  assert.equal(entry.action, "deny");
  assert.equal(entry.ruleId, "deny-rm");
  assert.equal(entry.source, "wrap");
  assert.equal(entry.sessionId, "s1");
  assert.equal(entry.outcome, "blocked");
  assert.equal("cwd" in entry, false);

  const bare = entryFromDecision(decision, "check");
  assert.equal("sessionId" in bare, false);
  assert.equal("outcome" in bare, false);
  assert.ok(!Number.isNaN(new Date(bare.ts).getTime()));
});

test("audit: parseSince understands durations, dates, all, and errors", () => {
  const now = new Date("2026-10-16T12:00:00.000Z");
  assert.equal(parseSince("30m", now)!.toISOString(), "2026-10-16T11:30:00.000Z");
  assert.equal(parseSince("24h", now)!.toISOString(), "2026-10-15T12:00:00.000Z");
  assert.equal(parseSince("7d", now)!.toISOString(), "2026-10-09T12:00:00.000Z");
  assert.equal(parseSince("all", now), null);
  assert.equal(parseSince("", now), null);
  assert.equal(parseSince("2026-10-01T00:00:00.000Z", now)!.toISOString(), "2026-10-01T00:00:00.000Z");
  assert.throws(() => parseSince("last tuesday", now), /invalid since/);
});

test("audit: filterEntries applies action, target, rule, since, and limit", () => {
  const entries = [
    sampleEntry({ ts: "2026-10-14T00:00:00.000Z", action: "allow" }),
    sampleEntry({ ts: "2026-10-15T00:00:00.000Z", action: "deny", ruleId: "r1" }),
    sampleEntry({
      ts: "2026-10-16T00:00:00.000Z",
      action: "deny",
      ruleId: "r2",
      target: "file",
      request: { target: "file", path: "a.ts" },
    }),
  ];
  assert.equal(filterEntries(entries, { action: "deny" }).length, 2);
  assert.equal(filterEntries(entries, { target: "file" }).length, 1);
  assert.equal(filterEntries(entries, { ruleId: "r1" }).length, 1);
  assert.equal(filterEntries(entries, { limit: 2 }).length, 2);
  assert.equal(filterEntries(entries, { limit: 2 })[0].ruleId, "r1");
  const since = new Date("2026-10-15T12:00:00.000Z");
  const recent = filterEntries(entries, { since });
  assert.equal(recent.length, 1);
  assert.equal(recent[0].ruleId, "r2");
});

test("audit: auditStats counts actions, targets, days, and top denied rules", () => {
  const entries = [
    sampleEntry({ ts: "2026-10-15T00:00:00.000Z", action: "deny", ruleId: "deny-a" }),
    sampleEntry({ ts: "2026-10-15T01:00:00.000Z", action: "deny", ruleId: "deny-a" }),
    sampleEntry({ ts: "2026-10-15T02:00:00.000Z", action: "deny", ruleId: null }),
    sampleEntry({ ts: "2026-10-16T00:00:00.000Z", action: "allow" }),
    sampleEntry({
      ts: "2026-10-16T01:00:00.000Z",
      action: "confirm",
      target: "network",
      request: { target: "network", host: "x.com" },
    }),
  ];
  const stats = auditStats(entries);
  assert.equal(stats.total, 5);
  assert.deepEqual(stats.byAction, { allow: 1, deny: 3, confirm: 1 });
  assert.deepEqual(stats.byTarget, { command: 4, file: 0, network: 1 });
  assert.deepEqual(stats.byDay, [
    { day: "2026-10-15", count: 3 },
    { day: "2026-10-16", count: 2 },
  ]);
  assert.deepEqual(stats.topDeniedRules[0], { ruleId: "deny-a", count: 2 });
  assert.deepEqual(stats.topDeniedRules[1], { ruleId: "(default)", count: 1 });
});

test("audit: formatAuditLine and summarizeRequest render one line", () => {
  const line = formatAuditLine(sampleEntry({ action: "deny", ruleId: "deny-rm", outcome: "blocked" }));
  assert.equal(line, "2026-10-16T00:00:00.000Z DENY command git status rule=deny-rm src=check outcome=blocked");
  assert.equal(summarizeRequest({ target: "file", path: "a/b.ts" }), "a/b.ts");
  assert.equal(summarizeRequest({ target: "network", host: "x.com" }), "x.com");
  assert.equal(summarizeRequest({ target: "network", url: "https://x.com/a" }), "https://x.com/a");
});

test("audit: sortNewestFirst orders newest first", () => {
  const a = sampleEntry({ ts: "2026-10-15T00:00:00.000Z" });
  const b = sampleEntry({ ts: "2026-10-17T00:00:00.000Z" });
  const sorted = sortNewestFirst([a, b]);
  assert.equal(sorted[0].ts, "2026-10-17T00:00:00.000Z");
  assert.equal(sorted[1].ts, "2026-10-15T00:00:00.000Z");
});

test("audit: resolveLogPath prefers explicit, then env, then the default", () => {
  const prev = process.env.AGENTGUARD_LOG;
  try {
    delete process.env.AGENTGUARD_LOG;
    assert.ok(defaultLogPath().includes(".agentguard"));
    assert.equal(resolveLogPath(), defaultLogPath());
    process.env.AGENTGUARD_LOG = "env-log.jsonl";
    assert.equal(resolveLogPath(), "env-log.jsonl");
    assert.equal(resolveLogPath("explicit.jsonl"), "explicit.jsonl");
  } finally {
    if (prev === undefined) delete process.env.AGENTGUARD_LOG;
    else process.env.AGENTGUARD_LOG = prev;
  }
});