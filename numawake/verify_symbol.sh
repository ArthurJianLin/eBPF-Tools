#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Verify select_task_rq_fair hook feasibility on Linux 4.19 (and newer).
# No BPF build required — uses kallsyms, BTF, perf/tracefs for attach tests.
#
# Usage: sudo ./verify_symbol.sh [-d SECONDS] [-s]

set -euo pipefail

TARGET="select_task_rq_fair"
DURATION=5
DO_STACK=0
TRACEFS="/sys/kernel/debug/tracing"
KPROBE_EVENTS="${TRACEFS}/kprobe_events"
PROBE_NAME="numawake_${TARGET}_$$"
PROBE_REMOVED=0

cleanup_probe() {
	if [[ "$PROBE_REMOVED" -eq 0 ]]; then
		remove_probe_by_name "$PROBE_NAME"
	fi
}

remove_probe_by_name() {
	local name="$1"
	if [[ ! -w "$KPROBE_EVENTS" ]]; then
		return
	fi
	while grep -qw "$name" "$KPROBE_EVENTS" 2>/dev/null; do
		echo "-:r:${name}" >> "$KPROBE_EVENTS" 2>/dev/null || \
		echo "-:kprobes/${name}" >> "$KPROBE_EVENTS" 2>/dev/null || break
	done
}

run_stack_sample() {
	local stack_dur="${1:-5}"
	local stack_probe="fair_stack_$$"
	local event_dir tmp total awk_stats wake lb other

	section "Caller stack sample (${stack_dur}s)"

	# Only one kretprobe per function: main probe must be fully removed first
	if [[ "$PROBE_REMOVED" -eq 0 && "$PROBE_OK" -eq 1 ]]; then
		echo 0 > "${TRACEFS}/events/kprobes/${PROBE_NAME}/enable" 2>/dev/null || true
		remove_probe_by_name "$PROBE_NAME"
		PROBE_REMOVED=1
	fi

	remove_probe_by_name "$stack_probe"
	while read -r line; do
		local stale
		stale=$(echo "$line" | awk '{print $1}' | sed 's/^r://;s/^r[0-9]*:kprobes\///')
		[[ -n "$stale" ]] && remove_probe_by_name "$stale"
	done < <(grep -E 'fair_stack' "$KPROBE_EVENTS" 2>/dev/null || true)

	if ! echo "r:${stack_probe} ${TARGET}" >> "$KPROBE_EVENTS" 2>&1; then
		echo "stack kretprobe attach: FAILED"
		tail -3 "$KPROBE_EVENTS" 2>/dev/null || true
		return 1
	fi

	event_dir="${TRACEFS}/events/kprobes/${stack_probe}"
	if [[ ! -d "$event_dir" ]]; then
		echo "event dir missing: ${event_dir}"
		grep "$stack_probe" "$KPROBE_EVENTS" 2>/dev/null || true
		remove_probe_by_name "$stack_probe"
		return 1
	fi

	echo "stack kretprobe attach: OK (r:${stack_probe})"
	echo "(format: caller <- ${TARGET})"

	# Improve kretprobe trace readability on 4.19
	echo 1 > "${TRACEFS}/tracing_on" 2>/dev/null || true
	[[ -w "${TRACEFS}/options/context_info" ]] && \
		echo 1 > "${TRACEFS}/options/context_info" 2>/dev/null || true
	[[ -w "${TRACEFS}/options/kprobes-callers" ]] && \
		echo 1 > "${TRACEFS}/options/kprobes-callers" 2>/dev/null || true
	echo > "${TRACEFS}/trace" 2>/dev/null || true

	echo 1 > "${event_dir}/enable"

	(for _ in $(seq 1 50000); do :; done) &
	local work_pid=$!

	tmp=$(mktemp)
	timeout "$stack_dur" cat "${TRACEFS}/trace_pipe" 2>/dev/null | \
		grep "$stack_probe" > "$tmp" || true

	wait "$work_pid" 2>/dev/null || true
	echo 0 > "${event_dir}/enable"
	remove_probe_by_name "$stack_probe"

	total=$(wc -l < "$tmp" | tr -d ' ')
	if [[ "$total" -eq 0 ]]; then
		echo "No stack samples captured."
		echo "Diagnostics:"
		echo "  tracing_on: $(cat "${TRACEFS}/tracing_on" 2>/dev/null || echo '?')"
		grep -E "fair_stack|${TARGET}" "$KPROBE_EVENTS" 2>/dev/null || \
			echo "  (no matching probes in kprobe_events)"
		if [[ -f "${event_dir}/format" ]]; then
			echo "  event format: $(head -1 "${event_dir}/format")"
		fi
		rm -f "$tmp"
		return 0
	fi

	echo "Total samples: ${total}"
	echo ""
	echo "Top callers (direct parent of ${TARGET}):"
	sed -n "s/.*(\\([^)]*\\) <- ${TARGET}).*/\\1/p" "$tmp" | \
		sed 's/+0x[0-9a-f]*\/0x[0-9a-f]*//' | sort | uniq -c | sort -rn | head -20

	echo ""
	echo "Wake-path vs load-balance heuristic:"
	awk_stats=$(awk '
		/try_to_wake_up|wake_up_|ttwu_/ { wake++ }
		/load_balance|balance_fair|active_load_balance|migrate_task|migration/ { lb++ }
		END { print wake+0, lb+0 }' "$tmp")
	wake=$(echo "$awk_stats" | awk '{print $1}')
	lb=$(echo "$awk_stats" | awk '{print $2}')
	other=$((total - wake - lb))
	if [[ "$other" -lt 0 ]]; then other=0; fi
	awk -v t="$total" -v w="$wake" -v l="$lb" -v o="$other" 'BEGIN {
		printf "  wake-like:  %d (%.1f%%)\n", w, 100*w/t
		printf "  LB/migrate: %d (%.1f%%)\n", l, 100*l/t
		printf "  other:      %d (%.1f%%)\n", o, 100*o/t
	}'
	rm -f "$tmp"
}

trap cleanup_probe EXIT

usage() {
	echo "Usage: $0 [-d SECONDS] [-s]"
	echo "  -d SECONDS   counting duration (default 5)"
	echo "  -s           also sample caller stacks (${TARGET} parent functions)"
	exit 1
}

while getopts "d:hs" opt; do
	case "$opt" in
	d) DURATION="$OPTARG" ;;
	s) DO_STACK=1 ;;
	h) usage ;;
	*) usage ;;
	esac
done

section() {
	echo ""
	echo "=== $1 ==="
}

# --- static checks ---
section "Kernel environment"
uname -a
echo "Kernel release: $(uname -r)"

section "Static symbol checks"
KSYM_LINE=$(grep -w "$TARGET" /proc/kallsyms 2>/dev/null | grep -v '\.cold' | head -1 || true)
if [[ -z "$KSYM_LINE" ]]; then
	KSYM_LINE=$(grep -w "$TARGET" /proc/kallsyms 2>/dev/null | head -1 || true)
fi
if [[ -z "$KSYM_LINE" ]]; then
	echo "kallsyms: NOT FOUND — kretprobe will fail"
	KSYM_OK=0
else
	echo "kallsyms: $KSYM_LINE"
	KSYM_TYPE=$(echo "$KSYM_LINE" | awk '{print $2}')
	echo "  symbol type '$KSYM_TYPE' (t=local/static, T=global)"
	KSYM_OK=1
fi

if [[ -r /sys/kernel/btf/vmlinux ]]; then
	echo "BTF vmlinux: available"
	if command -v bpftool >/dev/null 2>&1; then
		BTF_HIT=$(bpftool btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null \
			| grep -c "$TARGET" || true)
		echo "BTF func '$TARGET': $([[ "$BTF_HIT" -gt 0 ]] && echo found || echo not found)"
	else
		echo "BTF func: bpftool not installed, skipping BTF dump"
	fi
else
	echo "BTF vmlinux: not available (expected on 4.19)"
fi

echo ""
echo "4.19 expectation:"
echo "  - fexit/fentry: NOT supported (needs 5.5+)"
echo "  - BTF-based attach: NOT available (needs 5.4+ CONFIG_DEBUG_INFO_BTF)"
echo "  - kretprobe via kallsyms: supported if symbol in kallsyms (even type 't')"

# --- kretprobe attach test ---
section "Kretprobe attach test (tracefs)"
PROBE_OK=0

if [[ ! -w "$KPROBE_EVENTS" ]]; then
	echo "tracefs kprobe_events not writable — mount debugfs or run as root"
else
	if echo "r:${PROBE_NAME} ${TARGET}" >> "$KPROBE_EVENTS" 2>&1; then
		echo "kretprobe attach: OK (tracefs r:${PROBE_NAME})"
		PROBE_OK=1
	else
		echo "kretprobe attach: FAILED"
		tail -3 "$KPROBE_EVENTS" 2>/dev/null || true
	fi
fi

# --- live counting ---
section "Live counting (${DURATION}s)"

FAIR_DELTA=0
WAKE_DELTA=0
COUNT_METHOD="none"

if [[ "$PROBE_OK" -eq 1 ]]; then
	echo 1 > "${TRACEFS}/events/kprobes/${PROBE_NAME}/enable" 2>/dev/null || true
	echo 1 > "${TRACEFS}/events/sched/sched_wakeup/enable" 2>/dev/null || true
	echo 1 > "${TRACEFS}/events/sched/sched_wakeup_new/enable" 2>/dev/null || true

	(for _ in $(seq 1 50000); do :; done) &
	WORK_PID=$!

	if command -v perf >/dev/null 2>&1; then
		PERF_OUT=$(perf stat -a \
			-e "kprobes:${PROBE_NAME}" \
			-e "sched:sched_wakeup" \
			-e "sched:sched_wakeup_new" \
			sleep "$DURATION" 2>&1) && [[ "$PERF_OUT" != *"perf not found"* ]] && \
			COUNT_METHOD="perf"
	fi

	if [[ "$COUNT_METHOD" == "perf" ]]; then
		FAIR_DELTA=$(echo "$PERF_OUT" | awk -v p="$PROBE_NAME" '$0 ~ p {gsub(/,/,""); print $1; exit}')
		WAKE_CNT=$(echo "$PERF_OUT" | awk '/sched_wakeup[^_]/ {gsub(/,/,""); print $1; exit}')
		WAKE_NEW_CNT=$(echo "$PERF_OUT" | awk '/sched_wakeup_new/ {gsub(/,/,""); print $1; exit}')
		FAIR_DELTA=${FAIR_DELTA:-0}
		WAKE_CNT=${WAKE_CNT:-0}
		WAKE_NEW_CNT=${WAKE_NEW_CNT:-0}
		WAKE_DELTA=$((WAKE_CNT + WAKE_NEW_CNT))
	else
		COUNT_METHOD="trace_pipe"
		COUNTS=$(timeout "$DURATION" cat "${TRACEFS}/trace_pipe" 2>/dev/null | \
			awk -v p="$PROBE_NAME" '
			$0 ~ p { fair++ }
			/sched_wakeup_new:/ { wake++ }
			/sched_wakeup:/ { wake++ }
			END { print fair+0, wake+0 }' || true)
		FAIR_DELTA=$(echo "$COUNTS" | awk '{print $1}')
		WAKE_DELTA=$(echo "$COUNTS" | awk '{print $2}')
	fi

	wait "$WORK_PID" 2>/dev/null || true
	echo 0 > "${TRACEFS}/events/kprobes/${PROBE_NAME}/enable" 2>/dev/null || true
	echo 0 > "${TRACEFS}/events/sched/sched_wakeup/enable" 2>/dev/null || true
	echo 0 > "${TRACEFS}/events/sched/sched_wakeup_new/enable" 2>/dev/null || true
	# Free kretprobe slot before optional stack sample (-s)
	if [[ "$DO_STACK" -eq 1 && "$PROBE_OK" -eq 1 ]]; then
		remove_probe_by_name "$PROBE_NAME"
		PROBE_REMOVED=1
	fi
	echo "Count method: ${COUNT_METHOD}"
else
	echo "Skipping count — kretprobe attach failed"
fi

NON_WAKE=$((FAIR_DELTA > WAKE_DELTA ? FAIR_DELTA - WAKE_DELTA : 0))
if [[ "$FAIR_DELTA" -gt 0 ]]; then
	NON_WAKE_PCT=$(awk "BEGIN {printf \"%.1f\", 100.0 * $NON_WAKE / $FAIR_DELTA}")
else
	NON_WAKE_PCT="0.0"
fi

echo ""
echo "select_task_rq_fair (kretprobe): ${FAIR_DELTA}"
echo "sched_wakeup + sched_wakeup_new:  ${WAKE_DELTA}"
echo "estimated non-wake calls:         ${NON_WAKE} (${NON_WAKE_PCT}%)"
echo ""
echo "Interpretation:"
echo "  fair > wake      => non-wake LB calls ≈ fair - wake"
echo "  wake > fair      => many wakes skip select_task_rq_fair (non-CFS etc.)"
echo "  fair == 0        => no scheduler activity or probe not firing"

section "Summary"
echo "kallsyms:        $([[ "$KSYM_OK" -eq 1 ]] && echo OK || echo FAIL)"
echo "kretprobe attach:$([[ "$PROBE_OK" -eq 1 ]] && echo OK || echo FAIL)"
echo "fexit/BTF:       not applicable on 4.19 — use kretprobe"
if [[ "$PROBE_OK" -eq 1 && "$FAIR_DELTA" -gt 0 ]]; then
	echo "non-wake ratio:  ${NON_WAKE_PCT}% (${NON_WAKE}/${FAIR_DELTA})"
	echo "  (when wake>fair this metric is 0; use -s for caller breakdown)"
fi

if [[ "$DO_STACK" -eq 1 ]]; then
	run_stack_sample 5
fi
