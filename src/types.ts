export type TcpPeer = { local: string; peer: string };

export type Policy = {
  version: 1;
  cmd: string[];
  cwd: string;
  startedAt: string;
  durationMs: number;
  exit: number | null;
  tcp: TcpPeer[];
  writes: string[];
  sensitive: string[];
};

export const SENSITIVE_RES = [
  /\.ssh\b/,
  /\.gnupg\b/,
  /\.aws\b/,
  /\.npmrc$/,
  /\.netrc$/,
  /Keychains/,
  /\/etc\/(passwd|shadow|sudoers)/,
  /\.kube\b/,
  /\.docker\/config/,
];
