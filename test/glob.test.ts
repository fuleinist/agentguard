import { strict as assert } from "node:assert";
import { test } from "node:test";
import {
  anyGlobMatch,
  basenameOf,
  globMatch,
  globToRegExp,
  hasSeparator,
  normalizeHost,
  normalizePath,
} from "../src/glob.js";

test("glob: literal pattern matches itself", () => {
  assert.equal(globMatch("src/index.ts", "src/index.ts"), true);
  assert.equal(globMatch("src/index.ts", "src/other.ts"), false);
});

test("glob: * stays within one segment", () => {
  assert.equal(globMatch("src/*.ts", "src/app.ts"), true);
  assert.equal(globMatch("src/*.ts", "src/deep/app.ts"), false);
  assert.equal(globMatch("*.ts", "app.ts"), true);
  assert.equal(globMatch("*.ts", "src/app.ts"), false);
});

test("glob: ** crosses separators", () => {
  assert.equal(globMatch("src/**", "src/a/b.ts"), true);
  assert.equal(globMatch("src/**", "src/a"), true);
  assert.equal(globMatch("src/**", "src"), false);
  assert.equal(globMatch("src/**", "lib/a.ts"), false);
});

test("glob: leading **/ matches zero or more directories", () => {
  assert.equal(globMatch("**/foo", "foo"), true);
  assert.equal(globMatch("**/foo", "a/foo"), true);
  assert.equal(globMatch("**/foo", "a/b/foo"), true);
  assert.equal(globMatch("**/foo", "foo/x"), false);
  assert.equal(globMatch("**/.env", ".env"), true);
  assert.equal(globMatch("**/.env", "deep/.env"), true);
});

test("glob: ? matches one non-separator character", () => {
  assert.equal(globMatch("a?.ts", "ab.ts"), true);
  assert.equal(globMatch("a?.ts", "a.ts"), false);
  assert.equal(globMatch("a?.ts", "a/b.ts"), false);
});

test("glob: ** alone matches everything", () => {
  assert.equal(globMatch("**", "anything/at/all"), true);
  assert.equal(globMatch("**", ""), true);
});

test("glob: regex special characters in the pattern stay literal", () => {
  assert.equal(globMatch("file[1].ts", "file[1].ts"), true);
  assert.equal(globMatch("file[1].ts", "file1.ts"), false);
  assert.equal(globMatch("a+b.ts", "a+b.ts"), true);
  assert.equal(globMatch("a+b.ts", "aab.ts"), false);
});

test("glob: host pattern with dot separator", () => {
  const hostOpts = { sep: ".", caseInsensitive: true };
  assert.equal(globMatch("*.example.com", "api.example.com", hostOpts), true);
  assert.equal(globMatch("*.example.com", "example.com", hostOpts), false);
  assert.equal(globMatch("*.example.com", "www.api.example.com", hostOpts), false);
  assert.equal(globMatch("**.example.com", "www.api.example.com", hostOpts), true);
});

test("glob: case-insensitive option", () => {
  assert.equal(globMatch("API.Example.com", "api.example.com"), false);
  assert.equal(globMatch("API.Example.com", "api.example.com", { caseInsensitive: true }), true);
});

test("glob: globToRegExp anchors the pattern", () => {
  const re = globToRegExp("src/**");
  assert.equal(re.test("src/a"), true);
  assert.equal(re.test("xsrc/a"), false);
});

test("glob: anyGlobMatch checks a list", () => {
  assert.equal(anyGlobMatch(["src/**", "test/**"], "test/a.ts"), true);
  assert.equal(anyGlobMatch(["src/**", "test/**"], "docs/a.md"), false);
});

test("helpers: hasSeparator, basenameOf, normalizePath, normalizeHost", () => {
  assert.equal(hasSeparator("src/a.ts"), true);
  assert.equal(hasSeparator("*.pem"), false);
  assert.equal(basenameOf("a/b/c.ts"), "c.ts");
  assert.equal(basenameOf("c.ts"), "c.ts");
  assert.equal(normalizePath("src\\nested\\file.ts"), "src/nested/file.ts");
  assert.equal(normalizePath("./a//b.ts"), "a/b.ts");
  assert.equal(normalizePath("/abs//path"), "/abs/path");
  assert.equal(normalizeHost("  API.Example.COM. "), "api.example.com");
});