import { spawn } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { toSbpl } from "./sbpl.js";
import type { Policy } from "./types.js";

export async function runSealed(policy: Policy, cmd: string[], allowNet: boolean): Promise<number> {
  if (process.platform !== "darwin") {
    console.error("runlock run: sandbox-exec is macOS only. Use audit on this OS.");
    return 2;
  }
  const dir = await mkdtemp(path.join(os.tmpdir(), "runlock-"));
  const profile = path.join(dir, "profile.sb");
  await writeFile(profile, toSbpl(policy, { allowNet }));
  const child = spawn("sandbox-exec", ["-f", profile, ...cmd], { stdio: "inherit", cwd: policy.cwd });
  return await new Promise((resolve) => {
    child.on("exit", (code) => resolve(code ?? 1));
    child.on("error", () => resolve(127));
  });
}
