/**
 * Glob matching for file path and host patterns.
 *
 * Rules:
 * - "*"  matches any characters except the separator.
 * - "**" matches any characters, including the separator.
 * - "?"  matches exactly one character that is not the separator.
 * - The pattern is anchored: the whole text must match.
 */

export interface GlobOptions {
  /** Separator that a single "*" or "?" must not cross. Default: "/". */
  sep?: string;
  /** Case-insensitive matching. Default: false. */
  caseInsensitive?: boolean;
}

const REGEX_SPECIALS = /[.*+?^${}()|[\]\\]/;

function escapeRegExpChar(ch: string): string {
  return REGEX_SPECIALS.test(ch) ? `\\${ch}` : ch;
}

/** Compile a glob pattern into a regular expression. */
export function globToRegExp(pattern: string, options: GlobOptions = {}): RegExp {
  const sep = options.sep ?? "/";
  const sepRe = escapeRegExpChar(sep);
  let re = "^";

  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === "*") {
      if (pattern[i + 1] === "*") {
        if (pattern[i + 2] === sep) {
          // "**/" also matches zero directories.
          re += `(?:.*${sepRe})?`;
          i += 2;
        } else {
          re += ".*";
          i += 1;
        }
      } else {
        re += `[^${sepRe}]*`;
      }
    } else if (ch === "?") {
      re += `[^${sepRe}]`;
    } else {
      re += escapeRegExpChar(ch);
    }
  }

  re += "$";
  return new RegExp(re, options.caseInsensitive ? "i" : "");
}

/** True when `text` matches the glob `pattern`. */
export function globMatch(pattern: string, text: string, options: GlobOptions = {}): boolean {
  return globToRegExp(pattern, options).test(text);
}

/** True when `text` matches at least one pattern. */
export function anyGlobMatch(patterns: string[], text: string, options: GlobOptions = {}): boolean {
  return patterns.some((p) => globMatch(p, text, options));
}

/** True when the pattern contains a path separator. */
export function hasSeparator(pattern: string): boolean {
  return pattern.includes("/");
}

/** Return the last path segment. */
export function basenameOf(p: string): string {
  const idx = p.lastIndexOf("/");
  return idx === -1 ? p : p.slice(idx + 1);
}

/** Normalize a file path: forward slashes, no leading "./", collapsed "//". */
export function normalizePath(p: string): string {
  let out = p.replace(/\\/g, "/");
  out = out.replace(/^\.\//, "");
  out = out.replace(/(?<!^)\/{2,}/g, "/");
  return out;
}

/** Normalize a hostname: trim, lowercase, strip one trailing dot. */
export function normalizeHost(h: string): string {
  let out = h.trim().toLowerCase();
  out = out.replace(/\.$/, "");
  return out;
}