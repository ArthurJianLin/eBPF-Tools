# kvmpoll

观测 KVM `kvm_vcpu_wakeup` tracepoint，量化 halt poll 唤醒延迟分布与 OWN（host CPU 权衡）代价模型。面向 **Linux 4.19** KVM host（libbpf 0.5.0、`-mcpu=v1`）。

---

## `ns` 字段语义

| 路径 | `ns` 是什么 | 是否 host CPU 占用 |
|------|-------------|-------------------|
| success (`waited=0`) | poll 环内自旋时间 | 是 |
| fail (`waited=1`) | block 入口到退出的全周期 | 否（含 runqueue 睡眠） |

- `Σ fail ns` 不能当 host CPU 代价。
- `P50(fail) − P50(success)` 无物理意义，勿作 save_time。

---

## OWN 公式

```
OWN_exact  = (A × B) − C
OWN_approx = (A × B) − (D × E)
```

| 参数 | 含义 | 来源 |
|------|------|------|
| A | 成功拦截次数 | debugfs `halt_successful_poll` |
| B | VM-Exit+Entry 常数 | `-B`，默认 3200 ns |
| C | fail 路径 poll 预算累加 | eBPF（`kvm_halt_poll_ns` + `waited=1`） |
| D | fail 次数 | debugfs `halt_wakeup` 或 attempted−success−invalid |
| E | 自旋上限 | module `halt_poll_ns` |

>0 表示 net host CPU 收益；<0 表示 poll 浪费超过 schedule 节省。

---

## 指标与 tracepoint

| 指标 | Tracepoint |
|------|------------|
| success spin | `kvm/kvm_vcpu_wakeup` (`waited=0`) |
| fail block | `kvm/kvm_vcpu_wakeup` (`waited=1`) |
| poll budget (C) | `kvm/kvm_halt_poll_ns` |
| poll_actual | kprobe `kvm_vcpu_block` 入口 + `sched_switch` 睡下 |
| event_wait (B1) | `sched_switch` → `sched_wakeup` |
| runqueue (B2) | `sched_wakeup` → `sched_switch` |
| mechanism_tax | `fail_ns − poll_actual − event_wait`（配对 fail） |

直方图桶（µs）：`0–30`、`30–64`、`64–128`、`128–256`、`256–512`、`512–1024`、`1–2 ms`、`2+ ms`。

---

## 构建与运行

```bash
cd kvmpoll && make clean && make    # -> ../bin/kvmpoll

sudo ../bin/kvmpoll -p $(pidof qemu-system-x86_64) -i 10
sudo ../bin/kvmpoll -p $(pidof qemu-system-x86_64) -B 3200 -d 300 -q
sudo ../bin/kvmpoll -a --scan-interval 60
```

| 选项 | 说明 |
|------|------|
| `-p PID` | 监控 QEMU 线程组 |
| `-a` | 监控全部 QEMU（周期性 rescan） |
| `-i SEC` | 打印间隔（默认 10） |
| `-d SEC -q` | 固定时长采集，输出 `key=value` |
| `-B NS` | save_time 常数 B |
| `-H NS` | 覆盖 module `halt_poll_ns` 作为 E |

kprobe `kvm_vcpu_block` attach 失败时，`poll_actual` 回退为 poll budget，并打印 warning。

---

## 文件

| 文件 | 说明 |
|------|------|
| `kvmpoll.h` | ABI、直方图、OWN 辅助函数 |
| `kvmpoll.bpf.c` / `kvmpoll.c` | eBPF + userspace 主程序 |
