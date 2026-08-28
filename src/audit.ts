import { spawn } from "node:child_process";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import { classify, parseLsof } from "./parse.js";
import type { Policy, TcpPeer } from "./types.js";

export async function audit(cmd: string[], cwd: string, outPath: string): Promise<Policy> {
  const started = Date.now();
  const startedAt = new Date().toISOString();
  const child = spawn(cmd[0]!, cmd.slice(1), { cwd, stdio: "inherit" });
  const files = new Set<string>();
  const tcp = new Map<string, TcpPeer>();

  const tick = async () => {
    if (child.pid == null) return;
    const text = await lsof(child.pid);
    const parsed = parseLsof(text);
    for (const f of parsed.files) files.add(f);
    for (const t of parsed.tcp) tcp.set(`${t.local}->${t.peer}`, t);
  };

  const iv = setInterval(() => {
    void tick();
  }, 250);
  await tick();

  const exit = await new Promise<number | null>((resolve) => {
    child.on("exit", (code) => resolve(code));
    child.on("error", () => resolve(127));
  });
  clearInterval(iv);
  await tick();

  const classified = classify([...files], cwd);
  const policy: Policy = {
    version: 1,
    cmd,
    cwd,
    startedAt,
    durationMs: Date.now() - started,
    exit,
    tcp: [...tcp.values()],
    writes: classified.writes,
    sensitive: classified.sensitive,
  };
  await writeFile(outPath, JSON.stringify(policy, null, 2) + "\n");
  return policy;
}

async function lsof(pid: number): Promise<string> {
  return await new Promise((resolve) => {
    const p = spawn("lsof", ["-nP", "-p", String(pid)], { stdio: ["ignore", "pipe", "ignore"] });
    let out = "";
    p.stdout.on("data", (b) => {
      out += String(b);
    });
    p.on("close", () => resolve(out));
    p.on("error", () => resolve(""));
  });
}

export function defaultLock(cwd = process.cwd()): string {
  return path.join(cwd, ".runlock.json");
}
