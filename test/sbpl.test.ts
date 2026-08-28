import assert from "node:assert/strict";
import test from "node:test";
import { toSbpl } from "../src/sbpl.ts";
import type { Policy } from "../src/types.ts";

const base: Policy = {
  version: 1,
  cmd: ["echo", "hi"],
  cwd: "/tmp/proj",
  startedAt: "2026-08-28T00:00:00.000Z",
  durationMs: 1,
  exit: 0,
  tcp: [],
  writes: [],
  sensitive: [],
};

test("denies network when nothing was observed", () => {
  const s = toSbpl(base, { allowNet: false });
  assert.match(s, /\(deny network\*\)/);
  assert.match(s, /\/tmp\/proj/);
});

test("allows network when asked", () => {
  const s = toSbpl(base, { allowNet: true });
  assert.match(s, /\(allow network\*\)/);
});
test("denies reads of secret paths after allowing file-read", () => {
  const s = toSbpl(base, { allowNet: false });
  assert.match(s, /deny file-read\*/);
  assert.match(s, /\.ssh/);
});
