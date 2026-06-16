# select_task_rq_fair 符号验证结论

目标内核：**Linux 4.19**

## 结论

| 检查项 | 4.19 结果 | 说明 |
|--------|-----------|------|
| kallsyms 符号 | **存在** (`t select_task_rq_fair`) | `t` = 局部/static 符号，非 export；地址对非 root 显示为 0 是正常的 |
| BTF func | **不可用** | `CONFIG_DEBUG_INFO_BTF` 自 5.4 引入，4.19 无 `/sys/kernel/btf/vmlinux` |
| fexit/fentry attach | **不支持** | fentry/fexit 自 5.5 起可用，4.19 必须用 kretprobe |
| kretprobe attach | **可行** | 通过 kallsyms 解析 static 符号，与 export 符号挂载方式相同 |

**方案调整**：4.19 上 numawake MVP 应使用 `SEC("kretprobe/select_task_rq_fair")`，不能依赖 fexit/BTF/CO-RE 读参。

## 如何验证

### 方式 A：shell 脚本（无需编译 BPF）

在 4.19 目标机上以 root 运行：

```bash
cd numawake
sudo ./verify_symbol.sh -d 10
```

脚本会：
1. 检查 kallsyms / BTF
2. 通过 tracefs `kprobe_events` 尝试 `r:numawake_select_task_rq_fair`
3. 并行统计 `sched_wakeup` + `sched_wakeup_new` 与 kretprobe 命中次数
4. 估算 **非 wake 调用比例**

### 方式 B：BPF 工具（需 clang + libbpf）

```bash
cd numawake && make
sudo ../bin/verify_symbol -d 10
```

Makefile 使用 `vmlinux/4.19/` 头文件与 libbpf 0.5.0，与仓库其他 4.19 工具一致。

## 实测样例（Linux 7.0.0，kretprobe 验证 attach 机制）

在开发机上运行 `sudo ./verify_symbol.sh -d 3`：

```
kallsyms:        OK (t select_task_rq_fair)
BTF func:        not found（static 符号通常不在 BTF）
kretprobe attach: OK
select_task_rq_fair hits: 51361
sched_wakeup hits:        65914
non-wake (fair - wake):     0（wake > fair，说明部分 wake 不经 CFS 选核）
```

**4.19 上预期**：kretprobe attach 结果应与上类似（kallsyms 有 `t select_task_rq_fair` 即可）；BTF/fexit 仍不可用。

## 非 wake 调用比例

`select_task_rq_fair` 不仅被 `try_to_wake_up` 调用，还被以下路径调用：

- 周期性负载均衡（`load_balance`）
- active balance / migration
- 部分 `set_task_cpu` 迁移路径

因此 kretprobe 总命中数 **大于** `sched_wakeup` 事件数是预期行为。估算：

```
non_wake ≈ fair_kretprobe_hits - (sched_wakeup + sched_wakeup_new)
non_wake_pct = non_wake / fair_kretprobe_hits
```

**判读**：
- `non_wake_pct` 低（例如 <30%）且 `fair ≈ wake`：wake 路径占主导，kretprobe 适合做主锚点
- `non_wake_pct` 高：需在 BPF 内过滤（栈回溯、或与 `sched_waking` 时间关联）才能专盯 wake 路径

## kretprobe 读返回值（ideal_cpu）

4.19 无 BTF 时无法在 fexit 读参，但 kretprobe 可在返回时读 `pt_regs`：

- x86_64：`ideal_cpu = PT_REGS_RC(ctx)`（即 RAX 返回值）
- 入口参数 `prev_cpu`：需额外挂 `kprobe/select_task_rq_fair` 保存 `PT_REGS_PARM2(ctx)`（`struct task_struct *p` 为 parm1，`int prev_cpu` 为 parm2）

```c
SEC("kprobe/select_task_rq_fair")
int BPF_KPROBE(entry_select_task_rq_fair, struct task_struct *p, int prev_cpu, int sd_flags, int wake_flags)
{
    // save prev_cpu + pid to per-task map
    return 0;
}

SEC("kretprobe/select_task_rq_fair")
int BPF_KRETPROBE(ret_select_task_rq_fair)
{
    int ideal_cpu = PT_REGS_RC(ctx);
    // combine with saved prev_cpu
    return 0;
}
```

注意：4.19 `vmlinux.h` 中 `PT_REGS_*` 宏需与 `-D__TARGET_ARCH_x86` 一致；参数索引需对照内核 `select_task_rq_fair(struct task_struct *p, int prev_cpu, int sd_flags, int wake_flags)` 签名验证。

## 与计划原方案的对应

1. **fexit 锚点 1**：4.19 **不可行** → 改用 kretprobe + kprobe 配对
2. **sched_wakeup 锚点 2**：4.19 **完全可行**（tracepoint 自早期内核即有）
3. **sched_migrate_task 锚点 3**：**完全可行**；wake 路径上常在 `sched_wakeup` 之前触发，用于修正 `enqueue_cpu` 与 `enqueue_ts`（见 `numawake.bpf.c`）
4. **ideal vs target_cpu**：在 4.19 上仍几乎总是相等；主判据应为 `numa(prev_cpu) != numa(chosen_cpu)`（产品语义见 [SEMANTICS.md](SEMANTICS.md)）
5. **过滤非 wake**：必须作为独立工程项，不能假设 kretprobe 只命中 wake
