# eBPF 可观测性工具集

基于 [libbpf](https://github.com/libbpf/libbpf) 与 CO-RE（Compile Once – Run Everywhere）的 Linux 内核可观测性工具合集，覆盖内存、I/O、调度、虚拟化、文件系统与进程生命周期等场景。

## 工具一览

| 工具 | 目录 | 说明 |
|------|------|------|
| [slabtop](#slabtop) | `slabtop/` | 按进程统计 slab 内存分配速率，类似 `top` 的实时视图 |
| [mmap](#mmap) | `mmap/` | 追踪进程的 `mmap` / `munmap` 调用 |
| [mutex](#mutex) | `mutex/` | 统计 futex 锁竞争延迟直方图，支持调用栈 |
| [io](#io) | `io/` | 追踪块设备 I/O 请求，支持按进程、磁盘、延迟过滤 |
| [iofsstat](#iofsstat) | `iofsstat/` | 按进程/设备统计文件系统 I/O |
| [psrun](#psrun) | `psrun/` | 追踪进程调度等待时间，长等待时可打印调用栈 |
| [numawake](#numawake) | `numawake/` | 观测 CFS 唤醒路径上的跨 NUMA 决策、落地偏离与 runqueue 延迟（面向 Linux 4.19） |
| [pslife](#pslife) | `pslife/` | 追踪进程的 fork / kill 事件 |
| [funcstack](#funcstack) | `funcstack/` | 对内核函数挂 kprobe/kretprobe/tracepoint，打印调用栈 |
| [exec_trace](#exec_trace) | `exec_trace/` | 追踪执行指定命令的进程 |
| [filewatch](#filewatch) | `filewatch/` | 监控文件创建、删除与打开操作 |
| [kvmmon](#kvmmon) | `kvmmon/` | KVM vmexit→vmentry 延迟直方图，支持 Prometheus 导出 |

## 环境要求

- Linux 内核 ≥ 5.14（部分工具依赖 BTF / CO-RE）
- `clang`、`llvm`、`gcc`、`make`
- `libelf`、`zlib`、`zstd` 开发库
- root 权限（加载 BPF 程序需要 `CAP_BPF` / `CAP_PERFMON` 或 root）

## 构建

### 1. 准备依赖

```bash
# 将 libbpf 软链到项目根目录（指向本地 libbpf 仓库）
ln -s /path/to/libbpf libbpf

# bpftool 已预置在 tools/ 目录，也可自行替换为与内核版本匹配的版本
```

项目使用 libbpf **v1.5.0** 构建，各子目录 `Makefile` 会在编译时自动切换 libbpf 版本。例外：`numawake/` 面向 **Linux 4.19**，使用 libbpf **v0.5.0** 与 `vmlinux/4.19/` 头文件。

### 2. 编译单个工具

进入对应子目录执行 `make`，产物输出到 `bin/`：

```bash
cd slabtop && make    # 生成 ../bin/slabtop
cd io && make         # 生成 ../bin/io
# 其他工具同理
```

### 3. 编译全部工具

```bash
for d in slabtop mmap mutex io iofsstat psrun numawake pslife funcstack exec_trace filewatch kvmmon; do
    (cd "$d" && make)
done
```

## 工具说明

### slabtop

追踪各 slab kmem cache 的分配速率，支持按 PID 过滤与多列排序。

```bash
./bin/slabtop                  # 每秒刷新，按 size 排序
./bin/slabtop -p 181           # 仅追踪 PID 181
./bin/slabtop -s count         # 按 count 排序
./bin/slabtop -r 100           # 显示 100 行
./bin/slabtop 5 10             # 每 5 秒汇总，共 10 次
```

### mmap

追踪进程的内存映射与解除映射事件，可选将记录写入文件供后续分析。

```bash
./bin/mmap -p 1234             # 追踪指定 PID
./bin/mmap -c myapp            # 按进程名过滤
./bin/mmap -r                  # 将事件记录到 rd_mmap_data / rd_munmap_data
```

配合 `tools/mmap_analysis` 脚本可合并 mmap/munmap 记录并做内存分析。

### mutex

以直方图形式汇总 futex 锁竞争延迟，支持按 PID、TID、锁地址过滤。

```bash
./bin/mutex                    # 持续汇总
./bin/mutex 1 10               # 每秒输出，共 10 次
./bin/mutex -mT 1              # 毫秒级直方图 + 时间戳
./bin/mutex -p 123 -l 0x8187bb8
```

### io

追踪块层 I/O 请求，显示操作类型、延迟、进程与调用栈。

```bash
./bin/io -p 123                # 追踪指定进程
./bin/io -d vda                # 仅追踪 vda 磁盘
./bin/io -g 10                 # 仅显示延迟 > 10ms 的请求
```

### iofsstat

按进程、设备维度统计文件系统 I/O。

```bash
./bin/iofsstat -i 5 -n 10      # 每 5 秒输出，共 10 次
./bin/iofsstat -d vda          # 按设备过滤
./bin/iofsstat -p 1234         # 按 PID 过滤
./bin/iofsstat -c nginx        # 按进程名过滤
```

### psrun

追踪进程在调度器中的等待时间，超过阈值时打印内核/用户态调用栈。

```bash
./bin/psrun -p 123             # 追踪单个 PID
./bin/psrun -p 123,200-205     # 支持 PID 列表与范围
./bin/psrun -s 100             # 等待超过 100ms 时 dump 调用栈
```

### numawake

观测 CFS 唤醒路径上的 NUMA 相关调度决策：`select_task_rq_fair` 选核、`sched_wakeup` / `sched_migrate_task` 入队、`sched_switch` 首次运行。统计决策层跨 NUMA wake、入队与落地 CPU 偏离，以及 runqueue 等待延迟直方图。详见 [numawake/README.md](numawake/README.md) 与 [numawake/SEMANTICS.md](numawake/SEMANTICS.md)。

**目标内核：Linux 4.19**（kprobe/kretprobe，非 CO-RE）。建议先用 `verify_symbol` 确认 `select_task_rq_fair` 可挂载。

```bash
cd numawake && make            # 生成 ../bin/numawake、../bin/verify_symbol、../bin/numawake_topo
sudo ./bin/verify_symbol -d 5  # 验证探针与事件比例
sudo ./bin/numawake -i 3       # 每 3 秒打印累计统计
sudo ./bin/numawake -p 1234    # 仅追踪指定 PID
./bin/numawake_topo            # 查看 NUMA 拓扑
```

### pslife

追踪进程的 fork 与 kill 事件，记录时间戳与进程信息。

```bash
./bin/pslife                   # 追踪所有进程
./bin/pslife -p 123            # 仅追踪指定 PID 的子进程事件
```

### funcstack

对内核函数或 tracepoint 附加探针，在触发时打印调用栈。

```bash
./bin/funcstack -k vfs_read                        # kprobe
./bin/funcstack -r vfs_read                        # kretprobe
./bin/funcstack -t syscalls:sys_enter_execve       # tracepoint
./bin/funcstack -o sys_enter                       # raw tracepoint
```

### exec_trace

监控执行特定命令的进程。

```bash
./bin/exec_trace -c ls         # 追踪执行 ls 的进程
./bin/exec_trace -v            # 开启 libbpf 调试输出
```

### filewatch

监控文件系统操作：创建、删除，以及可选的文件打开。

```bash
./bin/filewatch                # 追踪 create / unlink
./bin/filewatch open           # 同时追踪 vfs_open
```

### kvmmon

监控 KVM 虚拟机的 vmexit→vmentry 延迟，支持单 QEMU 进程或全量监控 + Prometheus 指标导出。

```bash
./bin/kvmmon -p <qemu-pid>              # 监控单个 QEMU 进程
./bin/kvmmon -p <qemu-pid> -s 5000      # 延迟 ≥ 5µs 时打印内核栈
./bin/kvmmon -a -i 60                   # 监控所有 QEMU，每 60s 输出直方图
./bin/kvmmon -a --prom /path/to/vm_latency.prom
```

## 项目结构

```
.
├── libbpf/          # libbpf 软链（需自行准备）
├── tools/
│   ├── bpftool      # BPF 工具链
│   ├── libbpf.a.*   # 预编译的 libbpf 静态库
│   └── mmap_analysis
├── vmlinux/         # 各内核版本的 BTF 头文件
│   ├── 4.19/
│   └── 5.14/
├── bin/             # 编译产物（make 后生成）
├── slabtop/         # 各工具源码目录
├── mmap/
├── numawake/        # 跨 NUMA wake 观测（4.19）
├── ...
└── LICENSE
```

每个工具目录结构一致：

- `<tool>.bpf.c` — 内核态 BPF 程序
- `<tool>.c` — 用户态加载器
- `<tool>.skel.h` — bpftool 生成的 skeleton 头文件（编译时自动生成）
- `trace_helpers.c` — 符号解析、调用栈等公共辅助函数
- `Makefile`

## 注意事项

- 所有工具需要 root 权限运行。
- 内核需开启 `CONFIG_DEBUG_INFO_BTF` 以支持 CO-RE；部分工具在内核 4.19 上可使用 `vmlinux/4.19/` 头文件。
- **numawake** 专为 4.19 设计（`CONFIG_KALLSYMS_ALL` 下可挂 `select_task_rq_fair` kretprobe），不依赖内核 BTF。
- `RLIMIT_MEMLOCK` 不足时工具会自动尝试提升限制；若仍失败请手动调整。
- `filewatch` 等工具通过 kprobe 挂载，在高负载场景下可能有一定性能开销。

## License

[MIT](LICENSE)
