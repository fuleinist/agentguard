# agentguard

A policy firewall and audit log for coding agents.

Coding agents run commands, read and write files, and fetch URLs on your machine.
agentguard checks each action against a declarative policy and returns one of three
decisions: **allow**, **deny**, or **confirm**. Every decision goes to an audit log.

Enforce the policy in two ways:

- A Claude Code `PreToolUse` hook.
- A generic command wrapper: `agentguard wrap -- npm test`.

agentguard is local-first. It has zero runtime dependencies and makes no network calls.

## Why

- Block destructive commands (`rm -rf /`) before they run.
- Keep secrets off limits (`**/.env`, `**/*.pem`).
- Checkpoint elevated commands (`sudo`) with one prompt.
- Keep a searchable record of what your agents did.

## Quick start

Build from source:

```bash
git clone https://github.com/fuleinist/agentguard
cd agentguard
npm install
npm run build
npm link   # optional: puts `agentguard` on your PATH
```

Then in your project:

```bash
agentguard init                         # write agentguard.policy.json
agentguard validate                     # check the policy
agentguard check --command "rm -rf /"   # test one decision
```

## Decisions

Each request targets a **command**, a **file**, or a **network** host.

- `allow` — the action proceeds.
- `deny` — the action is blocked.
- `confirm` — a human must approve once.

Rules are ordered. The first matching rule wins. When no rule matches, the target
default applies.

## Compound commands

Agents chain commands: `git status && rm -rf /`. A naive check would see `git status`
and allow everything. agentguard splits compound commands on `&&`, `||`, `;`, `|`,
and newlines. It evaluates each segment. The strictest decision wins
(deny > confirm > allow).

## Policy file

`agentguard init` writes a starter policy. A small policy looks like this:

```json
{
  "name": "my policy",
  "defaults": { "command": "confirm", "file": "allow", "network": "confirm" },
  "rules": [
    {
      "id": "deny-secrets",
      "action": "deny",
      "target": "file",
      "match": { "paths": ["**/.env", "**/*.pem"] },
      "reason": "Credential files are off limits."
    },
    {
      "id": "deny-rm-rf",
      "action": "deny",
      "target": "command",
      "match": { "commands": ["\\brm\\s+-rf\\s+[/~]"], "mode": "regex" },
      "reason": "Recursive delete of root or home is blocked."
    },
    {
      "id": "allow-dev-tools",
      "action": "allow",
      "target": "command",
      "match": { "commands": ["git", "npm", "node"] },
      "reason": "Common development tools are allowed."
    }
  ]
}
```

### Rule fields

- `id` — unique name. It appears in decisions and audit entries.
- `action` — `allow`, `deny`, or `confirm`.
- `target` — `command`, `file`, or `network`.
- `match` — patterns for the target (below).
- `reason` — optional text shown on a match.
- `disabled` — optional. Disabled rules are skipped.

### Command match

- `commands` — list of patterns.
- `mode` — `exact`, `prefix` (default), or `regex`.
- Prefix mode uses word boundaries. `git` matches `git status`. It does not match
  `gitlab`.

### File match

- `paths` — list of glob patterns. A pattern with `/` matches the full path.
  A pattern without `/` matches the file name only.
- `operations` — optional filter: `read`, `write`.
- `**` crosses directories. `*` stays in one segment.

### Network match

- `hosts` — list of host globs. `*` stays in one label (`*.example.com`).
  `**` crosses labels (`**.example.com`).
- Ports are ignored. Matching is case-insensitive.

A fuller example lives in [`examples/policy.json`](examples/policy.json).

## Claude Code hook

Add this to your Claude Code settings (`.claude/settings.json` in the project,
or `~/.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Read|Write|Edit|MultiEdit|NotebookEdit|WebFetch",
        "hooks": [{ "type": "command", "command": "agentguard hook claude" }]
      }
    ]
  }
}
```

The hook maps tool calls to policy requests:

- `Bash` → command
- `Read` → file read
- `Write`, `Edit`, `MultiEdit`, `NotebookEdit` → file write
- `WebFetch` → network by URL host

Unmapped tools produce no output. Your normal permission flow continues.
If the policy is missing or invalid, the hook stays quiet by default.
Pass `--fail-closed` to deny instead.

A copy of the snippet lives in
[`examples/claude-settings.json`](examples/claude-settings.json).

## Command wrapper

Wrap any command that an agent asks you to run:

```bash
agentguard wrap -- npm test            # allow → runs
agentguard wrap --yes -- git push      # auto-approve a confirm rule
agentguard wrap --dry-run -- rm -rf /  # report the decision, run nothing
```

Exit codes: the child exit code passes through. `2` = denied.
`3` = declined or no TTY to ask.

## Audit log

Default path: `~/.agentguard/audit.jsonl`. One JSON line per decision.
Override with `--log <path>` or the `AGENTGUARD_LOG` variable.

```bash
agentguard log                              # newest 20 entries
agentguard log --action deny --since 7d     # filter
agentguard stats                            # totals and top denied rules
```

## CLI reference

| Command | Purpose |
| --- | --- |
| `agentguard init` | Write a starter policy. |
| `agentguard validate` | Check the policy. Show errors and warnings. |
| `agentguard check` | Evaluate one request. |
| `agentguard hook [claude]` | Run as a Claude Code hook. |
| `agentguard wrap` | Run a command through the policy. |
| `agentguard log` | Show audit entries. |
| `agentguard stats` | Summarize the audit log. |

Common options: `--policy <path>`, `--log <path>`.

Check exit codes: `0` allow, `2` deny, `3` confirm, `1` error.

## Notes and limits

- agentguard decides and logs. It is not a sandbox. It does not contain processes.
- Compound splitting is best effort. It does not parse the full shell grammar.
- On Windows, quote paths that contain spaces in `wrap`.
- Rules match the literal command string. A wrapper cannot see inside scripts.

## Development

```bash
npm run build
npm test
```

TypeScript, zero runtime dependencies, `node:test`, Node >= 20.

## Status

v0.1.0. Not published to npm yet. Build from source.

## License

MIT