/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef __KVMMON_H
#define __KVMMON_H

/* Max QEMU TGIDs monitored in -a mode (BPF hash sizes). */
#define KVMMON_MAX_MONITORED	256

/* arch/x86/kvm/trace.h: KVM_ISA_VMX / KVM_ISA_SVM */
#define KVM_ISA_VMX	1u
#define KVM_ISA_SVM	2u

/* VMX EXIT_REASON for HLT = 12,  SVM exit code for HLT = 0x78 */
#define VMX_EXIT_HLT	12u
#define SVM_EXIT_HLT	0x78u

/*
 * Microsecond buckets (kernel + userspace must match):
 *   [0]  0 - 64 us    (merged fine bins: former <1 … <64 µs)
 *   [1]  64 - 128 us [2] 128 - 256 us [3] 256 - 512 us
 *   [4]  512 - 1024 us [5] >= 1024 us
 */
#define KVM_HIST_SLOTS	6

struct kvm_hist {
	__u32 slots[KVM_HIST_SLOTS];
	__u64 sum_us; /* cumulative latency sum (µs), same as delta_ns/1000 bucketing */
};

struct kvm_pending {
	__u64 ts_ns;
	__u32 exit_reason;
	__u32 isa;
};

struct kvm_long_event {
	__u64 ts_ns;
	__u64 latency_ns;
	__u32 tgid;
	__u32 tid;
	__u32 exit_reason;
	__u32 isa;
	__s32 stack_id;
	__u32 _pad;
};

#endif
