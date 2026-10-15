/**
 * Core types for agentguard policies, requests, and decisions.
 */

/** The three decisions a rule can produce. */
export type Action = "allow" | "deny" | "confirm";

/** The three action surfaces agentguard governs. */
export type Target = "command" | "file" | "network";

/** File operation kinds. */
export type FileOperation = "read" | "write";

export interface CommandMatch {
  /** Command patterns, compared with `mode`. */
  commands: string[];
  /** Comparison mode. Default: "prefix". */
  mode?: "exact" | "prefix" | "regex";
}

export interface FileMatch {
  /**
   * Glob patterns. A pattern with "/" matches the full path.
   * A pattern without "/" matches the basename.
   */
  paths: string[];
  /** Optional filter: the rule matches only these operations. */
  operations?: FileOperation[];
}

export interface NetworkMatch {
  /** Host globs. "*" stays within one label. "**" crosses labels. */
  hosts: string[];
}

export interface Rule {
  /** Unique rule id. It appears in decisions and audit entries. */
  id: string;
  action: Action;
  target: Target;
  match: CommandMatch | FileMatch | NetworkMatch;
  /** Human-readable reason, shown on a match. */
  reason?: string;
  /** Disabled rules are skipped. */
  disabled?: boolean;
}

export interface PolicyDefaults {
  command: Action;
  file: Action;
  network: Action;
}

export interface Policy {
  $schema?: string;
  name?: string;
  /** Ordered rules. The first match wins. */
  rules: Rule[];
  /** Fallback actions when no rule matches. */
  defaults: PolicyDefaults;
}

/** One action to evaluate. */
export interface PolicyRequest {
  target: Target;
  /** Command line, when target is "command". */
  command?: string;
  /** File path, when target is "file". */
  path?: string;
  /** File operation, when target is "file". */
  operation?: FileOperation;
  /** Hostname, when target is "network". */
  host?: string;
  /** Full URL, when target is "network". */
  url?: string;
  /** Working directory context. */
  cwd?: string;
}

export interface Decision {
  action: Action;
  /** Matched rule id. null when a default applies. */
  ruleId: string | null;
  reason: string;
  request: PolicyRequest;
}

/** Built-in fallbacks when a policy omits `defaults`. */
export const BUILTIN_DEFAULTS: PolicyDefaults = {
  command: "confirm",
  file: "allow",
  network: "confirm",
};