import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { classify, parseLsof } from "../src/parse.ts";

const sample = readFileSync(new URL("../fixtures/lsof.txt", import.meta.url), "utf8");

test("parses tcp peers and files from lsof", () => {
  const p = parseLsof(sample);
  assert.ok(p.tcp.some((t) => t.peer.includes("443")));
  assert.ok(p.files.some((f) => f.includes(".ssh")));
});

test("flags ssh keys as sensitive", () => {
  const p = parseLsof(sample);
  const c = classify(p.files, "/Users/bugu/IndieHacker/demo");
  assert.ok(c.sensitive.some((s) => s.includes(".ssh")));
  assert.ok(c.writes.some((s) => s.includes("out.txt") || s.includes("demo")));
});
