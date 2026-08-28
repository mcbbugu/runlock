# runlock

English · [中文](README.zh.md)

Audit a local command, lock what it touched, rerun it under a macOS seatbelt.

Egret and harden-runner audit CI with eBPF, then emit an allowlist. runlock does that on your laptop, for the command a coding agent just generated.

```
runlock audit -- /bin/ls
runlock show
runlock run -- /bin/ls
```

## What is new

1. The lockfile is the product. .runlock.json records TCP peers, cwd files, and sensitive paths sampled from lsof while the child runs.
2. runlock diff is how you notice a second run phoned home somewhere new.
3. runlock run compiles that lock into a macOS sandbox-exec profile: writes limited to cwd and tmp, network denied unless the audit saw TCP. After allow file-read, the profile denies ~/.ssh, ~/.aws, kube/docker configs, and similar. Seatbelt cannot allowlist DNS names without a proxy, so enforcement is coarse on purpose.

This is not EDR and not an exploit kit. It is a lockfile plus a seatbelt for local, untrusted commands.

lsof sampling cannot prove writes without dtruss or root. The writes field is open files under cwd/tmp, not a syscall trace.

## Commands

```
npx tsx src/cli.ts audit -- /bin/ls
npx tsx src/cli.ts show
npx tsx src/cli.ts run -- /bin/ls
npx tsx src/cli.ts diff old.json new.json
```

Node 20+. run is Darwin-only. audit works anywhere lsof exists.

## Why

Coding agents emit untrusted commands without a second thought. CI already has StepSecurity Egret. Your laptop does not. runlock is the smallest lockfile that makes a second run fail closed when the command reaches somewhere new.

## License

MIT
