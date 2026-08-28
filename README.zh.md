# runlock

[English](README.md) · 中文

审计一条本地命令，锁住它碰到过的东西，再在 macOS seatbelt 里重跑。

Egret 和 harden-runner 用 eBPF 审计 CI，再吐出 allowlist。runlock 把同一件事做在笔记本上，对象是 coding agent 刚生成的那条命令。

```
runlock audit -- /bin/ls
runlock show
runlock run -- /bin/ls
```

## 新在哪

1. 产物是 lockfile。.runlock.json 记录 TCP 对端、cwd 下打开的文件、敏感路径（ssh、aws、kube、docker config），数据来自子进程运行时的 lsof 采样。
2. runlock diff 用来发现第二次运行多打了哪个电话。
3. runlock run 把 lock 编成 macOS sandbox-exec：写操作限制在 cwd 和 tmp；没见过 TCP 就禁网。允许读文件之后，会拒绝 ~/.ssh、~/.aws、kube/docker 配置等路径。Seatbelt 不能按域名放行，所以执行是粗粒度的，这是有意的。

这不是 EDR，也不是 exploit kit。就是一份 lockfile 加一层 seatbelt，给本机上不信任的命令用。

lsof 采样没法在没有 dtruss 或 root 时证明写入。writes 字段是 cwd/tmp 下打开过的文件，不是 syscall 追踪。

## 命令

```
npx tsx src/cli.ts audit -- /bin/ls
npx tsx src/cli.ts show
npx tsx src/cli.ts run -- /bin/ls
npx tsx src/cli.ts diff old.json new.json
```

需要 Node 20+。run 只在 Darwin 上可用。audit 只要有 lsof 就能跑。

## 为什么

Coding agent 会直接吐出不信任的命令。CI 已经有 StepSecurity Egret，笔记本没有。runlock 是最小的 lockfile：第二次运行如果摸到新地方，就失败关闭。

## License

MIT
