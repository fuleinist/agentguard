# agentguard — SPEC

A policy firewall and audit log for coding agents.

## Problem

Coding agents run commands, read and write files, and fetch URLs on your machine.
Today, most guardrails are hand-rolled scripts in blog posts.
Teams need one small, testable policy engine with an audit trail.

## Goal

Give developers a declarative policy file (JSON) that decides three things for each
agent action: **allow**, **deny**, or **confirm**.
Enforce the policy in two ways:

1. A Claude Code `PreToolUse` hook.
2. A generic command wrapper: `agentguard wrap -- <command>`.

Every decision goes to an append-only JSONL audit log.

## Non-goals

- No GUI. CLI only.
- No network calls. The tool is fully local.
- Not a sandbox. agentguard decides and logs. It does not isolate processes.

## Users and use cases

- Solo dev: block `rm -rf`, protect `.env` files, log everything agents do.
- Team: share one policy file in the repo and review audit logs together.
- Automation: wrap agent-driven commands so they follow the same rules.

## Features (v0.1)

### F1 — Policy file

- JSON file `agentguard.policy.json`.
- `defaults` per target plus an ordered `rules` list.
- Rule fields: `id`, `action` (allow|deny|confirm), `target` (command|file|network),
  `match`, optional `reason`, optional `disabled`.
- Command match: `commands` plus `mode` (exact|prefix|regex; default prefix).
- File match: `paths` (glob; a pattern with `/` matches the full path, else the
  basename), optional `operations` (read|write).
- Network match: `hosts` (host globs; `*` stays in one label, `**` crosses labels).
- First matching rule wins. Rules run top to bottom.

### F2 — Engine

- `evaluate(policy, request) -> Decision { action, ruleId, reason }`.
- No match: the target default applies.

### F3 — Audit log

- JSONL, one line per decision: ts, action, target, request, ruleId, reason, source,
  sessionId, outcome.
- Default path `~/.agentguard/audit.jsonl`.
- Override with `--log` or `AGENTGUARD_LOG`.

### F4 — Claude Code hook

- `agentguard hook claude` reads the PreToolUse JSON on stdin.
- Maps Bash, Read, Write, Edit, MultiEdit, NotebookEdit, and WebFetch.
- Emits `hookSpecificOutput.permissionDecision` allow|deny|ask.
- Unmapped tools: no opinion (exit 0, no output).

### F5 — Command wrapper

- `agentguard wrap [--yes] [--dry-run] -- <command>`.
- allow: run the command.
- deny: block it (exit 2).
- confirm: prompt once. `--yes` auto-accepts. No TTY: decline (exit 3).

### F6 — CLI

- Commands: `init`, `validate`, `check`, `hook`, `wrap`, `log`, `stats`, `version`.
- Exit codes for `check`: 0 allow, 2 deny, 3 confirm, 1 error.

## Acceptance criteria

1. `npm run build` is clean with TypeScript strict.
2. `node --test` passes all tests (target: 60+ across the suite).
3. `agentguard check --command "rm -rf /"` denies with a named rule.
4. A hook run with a fake PreToolUse payload prints valid decision JSON and appends
   one audit line.
5. `wrap` runs an allowed command and blocks a denied one in a live demo.
6. README documents the policy format, hook setup, and CLI usage.

## Constraints

- TypeScript 5.9, zero runtime dependencies, node:test, Node >= 20.
- No network access at runtime.
- Docs use Simplified Technical English: short sentences, active voice.

## Risks

- The hook JSON format may change. Keep the mapper small and testable.
- Windows shell quoting in `wrap` is tricky. Document the caveat.