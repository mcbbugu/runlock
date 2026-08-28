#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { audit, defaultLock } from "./audit.js";
import { runSealed } from "./run.js";
import { toSbpl } from "./sbpl.js";
import type { Policy } from "./types.js";

const argv = process.argv.slice(2);
const help = `runlock — audit a command, lock what it touched, rerun under a seatbelt

  runlock audit [--] <cmd...>     sample lsof while it runs, write .runlock.json
  runlock run [--net] [--] <cmd...>
                                  macOS sandbox-exec from the lockfile
  runlock show                    print lock + generated sbpl
  runlock diff <a.json> <b.json>  new tcp peers / sensitive paths
`;

if (!argv.length || argv[0] === "-h" || argv[0] === "--help") {
  console.log(help);
  process.exit(argv.length ? 0 : 1);
}

const cmdIndex = (a: string[], i: number) => {
  const rest = a.slice(i);
  if (rest[0] === "--") return rest.slice(1);
  return rest;
};

const sub = argv[0];
const cwd = process.cwd();
const lockPath = defaultLock(cwd);

if (sub === "audit") {
  const cmd = cmdIndex(argv, 1);
  if (!cmd.length) {
    console.error("runlock audit needs a command");
    process.exit(1);
  }
  const policy = await audit(cmd, cwd, lockPath);
  printSummary(policy, lockPath);
  process.exit(policy.exit ?? 0);
}

if (sub === "run") {
  const net = argv.includes("--net");
  const cmd = cmdIndex(argv.filter((a) => a !== "--net"), 1);
  const policy = await load(lockPath);
  const use = cmd.length ? cmd : policy.cmd;
  const code = await runSealed(policy, use, net || policy.tcp.length > 0);
  process.exit(code);
}

if (sub === "show") {
  const policy = await load(lockPath);
  printSummary(policy, lockPath);
  console.log("\n--- sandbox-exec profile ---\n");
  console.log(toSbpl(policy, { allowNet: policy.tcp.length > 0 }));
  process.exit(0);
}

if (sub === "diff") {
  const a = await load(argv[1] ?? lockPath);
  const b = await load(argv[2] ?? "");
  const peersA = new Set(a.tcp.map((t) => t.peer));
  const newPeers = b.tcp.filter((t) => !peersA.has(t.peer));
  const sensA = new Set(a.sensitive);
  const newSens = b.sensitive.filter((s) => !sensA.has(s));
  console.log("new peers:");
  for (const p of newPeers) console.log("  " + p.peer);
  console.log("new sensitive:");
  for (const s of newSens) console.log("  " + s);
  process.exit(newPeers.length || newSens.length ? 1 : 0);
}

console.error(help);
process.exit(1);

async function load(p: string): Promise<Policy> {
  if (!p) throw new Error("need a lockfile path");
  return JSON.parse(await readFile(p, "utf8")) as Policy;
}

function printSummary(p: Policy, file: string) {
  console.log("wrote " + file);
  console.log("exit " + String(p.exit) + " in " + p.durationMs + "ms");
  console.log("tcp " + p.tcp.length + "  writes " + p.writes.length + "  sensitive " + p.sensitive.length);
  for (const t of p.tcp.slice(0, 12)) console.log("  net " + t.peer);
  for (const s of p.sensitive.slice(0, 12)) console.log("  sensitive " + s);
}
