# numawake 产品语义：「不公平」指标定义

本文档明确 numawake 工具输出的两类 NUMA 相关事件及其判据，供 BPF 实现与用户态聚合共用。

## 背景：唤醒路径上的三个 CPU

一次 CFS 唤醒在观测上涉及三个不同的 CPU 概念，**不可混用**：

| 字段 | 来源 | 含义 |
|------|------|------|
| `prev_cpu` | `select_task_rq_fair` 入口参数 | 唤醒**前**任务所在 CPU |
| `chosen_cpu` | `select_task_rq_fair` 返回值（ideal_cpu）；与 `sched_wakeup.target_cpu` 在常态下相同 | 调度器**决策**的入队 CPU |
| `enqueue_cpu` | `sched_wakeup` / `sched_migrate_task` 修正后 | 任务**最终入队**的 CPU（migrate 可能改写入队核） |
| `first_run_cpu` | `sched_switch` 中 `next_pid` 命中时的 `bpf_get_smp_processor_id()` | 唤醒后**首次运行**的 CPU |

典型顺序：

```
select_task_rq_fair(prev_cpu → chosen_cpu)
  → [可选] sched_migrate_task(enqueue_cpu 修正)
  → sched_wakeup(enqueue_cpu)
  → runqueue 等待
  → sched_switch(first_run_cpu)
```

**`sched_wakeup.target_cpu` 不是「实际运行核」**，只是决策入队核；与 `chosen_cpu` 几乎总相等，**不得**作为主 detector。

---

## 指标一（主指标）：决策层跨 NUMA — `CROSS_NUMA_WAKE`

### 判据

```
node(prev_cpu) != node(chosen_cpu)
```

其中 `node(cpu)` 来自用户态配置的 `cpu_to_node[]` map（见 topology-map todo）。

### 语义

CFS 在 **wake 选核** 时主动把任务放到与 `prev_cpu` 不同 NUMA 节点的 CPU 上。常见触发包括 wake-wide 搜索、idle CPU 搜索、NUMA balancing、内存策略与 cpuset 约束下的合法迁移等。

### 产品定位

- **默认开启统计与直方图**；CLI 汇总中的 `cross_numa_wake` 计数指此指标。
- 名称保留「wake」以强调事件锚定在 wake 路径，而非周期性 load balance（后者需过滤 `select_task_rq_fair` 非 wake 调用）。
- **不等于 bug**：跨 NUMA 可能是调度器预期行为；工具输出「发生了决策层跨 NUMA wake + 延迟分布」，**不自动判定为 unfair**，除非用户另行配置 baseline（见下文「Baseline 与告警」）。

### 延迟

`latency_ns = t(first_sched_switch) - t(last_enqueue_decision)`

- `last_enqueue_decision`：**入队前**最后一次确定入队 CPU 的时间戳——最后一次 pre-wakeup `sched_migrate_task`，否则为 `sched_wakeup`。入队后的 migrate 不参与（见 [README.md](README.md) §重点逻辑）。
- 该延迟本质是 **runqueue 等待时间**（与 [psrun](../psrun/psrun.bpf.c) 相同），是跨 NUMA wake 的**相关代价 proxy**，**不能**称为「NUMA 内存搬移延迟」或「远端内存访问延迟」。

### 输出事件标志

`NUMAWAKE_F_CROSS_NUMA_WAKE`（见 `numawake.h`）

---

## 指标二（辅指标）：落地层偏离 — `LANDING_DEVIATION`

### 判据

```
enqueue_cpu != first_run_cpu
```

需同时 hook `sched_migrate_task` 与 `sched_switch` 才能可靠判定。

### 语义

任务在 wake **决策并入队之后**、**首次运行之前**，又被迁移到其他 CPU（负载均衡 pull、active balance、二次 `sched_migrate_task` 等）。表示 **实际落地 CPU 偏离入队决策**，与「选核算法算错」不是同一类问题。

### 产品定位

- **独立计数** `landing_deviation`；与指标一并输出 ideal / enqueue / first_run 三方 CPU，便于区分「决策跨 NUMA」与「入队后又跑别处」。
- **默认不作为主告警条件**；适合诊断「wake 之后又被拽走」的路径。
- 可与指标一叠加：例如决策层同 NUMA 但落地层跨 NUMA（`node(enqueue_cpu) != node(first_run_cpu)` 且 `node(prev_cpu) == node(chosen_cpu)`）单独分桶统计。

### 延迟

指标二的延迟字段与指标一共用同一次 wake 的 `latency_ns`（从 `last_enqueue_decision` 到 `first_run`）。若仅发生落地偏离而决策层同 NUMA，仍记录延迟，但 **不** 计入 `cross_numa_wake`。

### 输出事件标志

`NUMAWAKE_F_LANDING_DEVIATION`（见 `numawake.h`）

---

## 明确排除：ideal vs sched_wakeup（含义 C）

### 判据（不采用）

```
chosen_cpu != sched_wakeup.target_cpu
```

### 原因

内核在 `select_task_rq_fair` 返回后会 `set_task_cpu(p, cpu)` 再 `ttwu_queue()`；tracepoint 中的 `target_cpu` 即 `task_cpu(p)`。二者 **几乎总相等**，事件量趋近于零，**不适合**作为主 detector 或「应该 vs 实际」叙事。

### 实现用途

仅作 **sanity check**：用户态或 debug 模式下统计 `chosen_cpu != enqueue_cpu` 次数，用于验证 BPF 与内核 trace 对齐，**不进入** `cross_numa_wake` / `landing_deviation` 计数。

---

## Baseline 与告警（产品层约定）

MVP **默认 baseline**：`node(prev_cpu)` —— 即「若调度器不跨节点，任务应继续留在唤醒前所在 NUMA 节点」。在此 baseline 下：

| 观测 | MVP 行为 |
|------|----------|
| `node(prev_cpu) != node(chosen_cpu)` | 记为 `CROSS_NUMA_WAKE` 事件 + 延迟直方图 |
| `enqueue_cpu != first_run_cpu` | 记为 `LANDING_DEVIATION` 事件 |
| 二者同时成立 | 同一事件可同时带两个 flag |

**不在 MVP 范围、后续可扩展的 baseline**（当前 **不** 自动判 unfair）：

- 与 **cpuset / 内存策略允许集合** 对比的「期望节点」
- 与 **task 内存所在 node**（需额外 hook NUMA fault / `numa_migrate`）对比
- 与 **用户指定 `-N expected_node`** 对比

在未配置扩展 baseline 前，工具文案应使用 **「cross NUMA wake」** / **「landing deviation」**，避免单独使用 **「unfair」** 一词，以免暗示已做期望对比。

---

## 用户态汇总字段（MVP）

| 字段 | 含义 |
|------|------|
| `cross_numa_wake` | 指标一事件数 |
| `landing_deviation` | 指标二事件数 |
| `same_numa_wake` | 决策层同 NUMA 的 wake 数（对照组，用于延迟对比） |
| `sanity_mismatch` | `chosen_cpu != enqueue_cpu`（debug） |
| 直方图 | 按 `cross_numa_wake` / `same_numa_wake` **分桶**的 runqueue latency |

---

## 与后续 todo 的接口

- **add-migrate-tp**：已实现于 `numawake.bpf.c`；pre-wakeup migrate 锚定 `enqueue_ts`，`SEEN_WAKEUP` 后忽略 migrate；生命周期见 README §重点逻辑。
- **topology-map**：`node(cpu)` 来自用户态 `numawake_topology.c` 解析 `/sys/devices/system/node/node*/cpulist` 并写入 BPF `cpu_to_node_map`。
- **mvp-psrun-pattern**：`pending_wake` map 字段与 `struct numawake_event` 见 `numawake.h`。
