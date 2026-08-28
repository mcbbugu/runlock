import { SENSITIVE_RES, type TcpPeer } from "./types.js";

export function parseLsof(text: string): { files: string[]; tcp: TcpPeer[] } {
  const files = new Set<string>();
  const tcp = new Map<string, TcpPeer>();
  for (const line of text.split(/\n/)) {
    if (!line || line.startsWith("COMMAND")) continue;
    const tcpHit = line.match(/\bTCP\s+(\S+)->(\S+)/);
    if (tcpHit) {
      const local = tcpHit[1]!.replace(/\s.*/g, "");
      const peer = tcpHit[2]!.replace(/\s.*/g, "");
      tcp.set(`${local}->${peer}`, { local, peer });
      continue;
    }
    const parts = line.trim().split(/\s+/);
    if (parts.length < 9) continue;
    const name = parts.slice(8).join(" ");
    if (name.startsWith("/") || name.startsWith("~")) files.add(name.split(" \\(")[0]!);
  }
  return { files: [...files], tcp: [...tcp.values()] };
}

export function classify(files: string[], cwd: string): { writes: string[]; sensitive: string[] } {
  const writes: string[] = [];
  const sensitive: string[] = [];
  for (const f of files) {
    if (SENSITIVE_RES.some((r) => r.test(f))) sensitive.push(f);
    if (f.startsWith(cwd) || f.startsWith("/tmp") || f.startsWith("/private/tmp") || f.startsWith("/var/folders")) {
      writes.push(f);
    }
  }
  return { writes: uniq(writes), sensitive: uniq(sensitive) };
}

function uniq(xs: string[]): string[] {
  return [...new Set(xs)];
}
