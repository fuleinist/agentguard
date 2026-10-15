/**
 * The decision engine. It evaluates one request against a policy.
 *
 * Command safety: compound commands (&&, ||, ;, |, newline) are split into
 * segments. Each segment is evaluated. The strictest decision wins
 * (deny > confirm > allow).
 */

import { basenameOf, globMatch, hasSeparator, normalizeHost, normalizePath } from "./glob.js";
import { BUILTIN_DEFAULTS } from "./types.js";
import type {
  CommandMatch,
  Decision,
  FileMatch,
  FileOperation,
  NetworkMatch,
  Policy,
  PolicyRequest,
  Rule,
} from "./types.js";

const STRICTNESS: Record<Decision["action"], number> = { deny: 2, confirm: 1, allow: 0 };

/** Trim and collapse whitespace runs. */
export function normalizeCommand(command: string): string {
  return command.trim().replace(/\s+/g, " ");
}

/** Split a compound command into segments on &&, ||, ;, |, and newlines. */
export function splitCompoundCommand(command: string): string[] {
  return command
    .split(/&&|\|\||[;|\n]/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function isWordChar(ch: string): boolean {
  return /[A-Za-z0-9_]/.test(ch);
}

/**
 * Prefix match with a word boundary. "git" matches "git status" but not "gitlab".
 * A pattern that ends with a non-word character matches freely.
 */
function prefixMatch(command: string, pattern: string): boolean {
  if (!command.startsWith(pattern)) return false;
  const next = command.charAt(pattern.length);
  const last = pattern.charAt(pattern.length - 1);
  return !(isWordChar(last) && isWordChar(next));
}

function matchCommand(m: CommandMatch, commandRaw: string): boolean {
  const mode = m.mode ?? "prefix";
  const command = normalizeCommand(commandRaw);
  for (const patternRaw of m.commands) {
    if (mode === "regex") {
      let re: RegExp;
      try {
        re = new RegExp(patternRaw);
      } catch {
        throw new Error(`invalid regex pattern: ${patternRaw}`);
      }
      if (re.test(commandRaw.trim())) return true;
    } else {
      const pattern = normalizeCommand(patternRaw);
      if (mode === "exact") {
        if (command === pattern) return true;
      } else if (prefixMatch(command, pattern)) {
        return true;
      }
    }
  }
  return false;
}

function matchFile(m: FileMatch, pathRaw: string, operation?: FileOperation): boolean {
  if (m.operations !== undefined) {
    if (operation === undefined || !m.operations.includes(operation)) return false;
  }
  const path = normalizePath(pathRaw);
  const base = basenameOf(path);
  for (const raw of m.paths) {
    const pattern = normalizePath(raw);
    const target = hasSeparator(pattern) ? path : base;
    if (globMatch(pattern, target)) return true;
  }
  return false;
}

function stripPort(host: string): string {
  return /^[^:]+:\d+$/.test(host) ? host.replace(/:\d+$/, "") : host;
}

function matchNetwork(m: NetworkMatch, hostRaw: string): boolean {
  const host = stripPort(normalizeHost(hostRaw));
  return m.hosts.some((pattern) => globMatch(normalizeHost(pattern), host, { sep: ".", caseInsensitive: true }));
}

/** True when the rule matches the request. Disabled rules never match. */
export function ruleMatches(rule: Rule, request: PolicyRequest): boolean {
  if (rule.disabled) return false;
  switch (rule.target) {
    case "command":
      return matchCommand(rule.match as CommandMatch, request.command ?? "");
    case "file":
      return matchFile(rule.match as FileMatch, request.path ?? "", request.operation);
    case "network":
      return matchNetwork(rule.match as NetworkMatch, request.host ?? "");
    default:
      return false;
  }
}

/** Return the first matching rule, or null. */
export function findMatchingRule(policy: Policy, request: PolicyRequest): Rule | null {
  for (const rule of policy.rules) {
    if (rule.target !== request.target) continue;
    if (ruleMatches(rule, request)) return rule;
  }
  return null;
}

function normalizeRequest(request: PolicyRequest): PolicyRequest {
  if (request.target === "command") {
    if (!request.command || request.command.trim() === "") {
      throw new Error("command target requires a non-empty command");
    }
    return request;
  }
  if (request.target === "file") {
    if (!request.path || request.path.trim() === "") {
      throw new Error("file target requires a non-empty path");
    }
    return request;
  }
  if (request.target === "network") {
    if (request.host && request.host.trim() !== "") return request;
    if (request.url) {
      let hostname: string;
      try {
        hostname = new URL(request.url).hostname;
      } catch {
        throw new Error(`invalid URL: ${request.url}`);
      }
      if (!hostname) throw new Error(`cannot derive host from URL: ${request.url}`);
      return { ...request, host: hostname };
    }
    throw new Error("network target requires a host or a URL");
  }
  throw new Error(`unknown request target: ${String(request.target)}`);
}

function decisionFromRule(rule: Rule, request: PolicyRequest): Decision {
  return {
    action: rule.action,
    ruleId: rule.id,
    reason: rule.reason ?? `matched rule "${rule.id}"`,
    request,
  };
}

function defaultDecision(policy: Policy, request: PolicyRequest): Decision {
  const action = policy.defaults?.[request.target] ?? BUILTIN_DEFAULTS[request.target];
  return { action, ruleId: null, reason: `no rule matched; default for ${request.target}`, request };
}

function decideSingle(policy: Policy, request: PolicyRequest): Decision {
  const rule = findMatchingRule(policy, request);
  return rule ? decisionFromRule(rule, request) : defaultDecision(policy, request);
}

function pickStricter(a: Decision, b: Decision): Decision {
  return STRICTNESS[a.action] >= STRICTNESS[b.action] ? a : b;
}

function evaluateCommand(policy: Policy, request: PolicyRequest): Decision {
  const segments = splitCompoundCommand(request.command ?? "");
  if (segments.length <= 1) {
    return decideSingle(policy, request);
  }
  let combined: Decision | null = null;
  for (const segment of segments) {
    const segRequest: PolicyRequest = { ...request, command: segment };
    const decision = decideSingle(policy, segRequest);
    combined = combined === null ? decision : pickStricter(combined, decision);
  }
  if (combined === null) return decideSingle(policy, request);
  return { ...combined, request };
}

/** Evaluate one request against the policy. Throws on a malformed request. */
export function evaluate(policy: Policy, request: PolicyRequest): Decision {
  const req = normalizeRequest(request);
  if (req.target === "command") {
    return evaluateCommand(policy, req);
  }
  return decideSingle(policy, req);
}