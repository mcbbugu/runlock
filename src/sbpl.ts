import type { Policy } from "./types.js";

const SECRET_RES = [
  ".*\\.ssh/.*",
  ".*\\.gnupg/.*",
  ".*\\.aws/.*",
  ".*\\.kube/.*",
  ".*\\.docker/config",
  ".*\\.npmrc$",
  ".*\\.netrc$",
  ".*/Keychains/.*",
  ".*/etc/(passwd|shadow|sudoers)",
];

/** macOS sandbox-exec profile. Coarse on purpose: seatbelt cannot allowlist DNS names. */
export function toSbpl(policy: Policy, opts: { allowNet: boolean }): string {
  const cwd = json(policy.cwd);
  const secrets = SECRET_RES.map((r) => "(regex " + json(r) + ")").join(" ");
  const lines = [
    "(version 1)",
    "(deny default)",
    "(allow process*)",
    "(allow signal)",
    "(allow sysctl-read)",
    "(allow mach-lookup)",
    "(allow file-read*)",
    "(deny file-read* " + secrets + ")",
    "(allow file-write* (subpath \"/tmp\") (subpath \"/private/tmp\") (subpath \"/var/folders\") (subpath " + cwd + "))",
    "(allow file-ioctl)",
    "(allow ipc-posix*)",
  ];
  if (opts.allowNet || policy.tcp.length) {
    lines.push("(allow network*)");
  } else {
    lines.push("(deny network*)");
  }
  return lines.join("\n") + "\n";
}

function json(s: string): string {
  return JSON.stringify(s);
}
