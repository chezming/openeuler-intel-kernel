/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARCH_X86_KVM_X86_H
#define ARCH_X86_KVM_X86_H

#include <linux/kvm_host.h>
#include <asm/pvclock.h>
#include "kvm_cache_regs.h"
#include "kvm_emulate.h"

#define KVM_DEFAULT_PLE_GAP		128
#define KVM_VMX_DEFAULT_PLE_WINDOW	4096
#define KVM_DEFAULT_PLE_WINDOW_GROW	2
#define KVM_DEFAULT_PLE_WINDOW_SHRINK	0
#define KVM_VMX_DEFAULT_PLE_WINDOW_MAX	UINT_MAX
#define KVM_SVM_DEFAULT_PLE_WINDOW_MAX	USHRT_MAX
#define KVM_SVM_DEFAULT_PLE_WINDOW	3000

static inline unsigned int __grow_ple_window(unsigned int val,
		unsigned int base, unsigned int modifier, unsigned int max)
{
	u64 ret = val;

	if (modifier < 1)
		return base;

	if (modifier < base)
		ret *= modifier;
	else
		ret += modifier;

	return min(ret, (u64)max);
}

static inline unsigned int __shrink_ple_window(unsigned int val,
		unsigned int base, unsigned int modifier, unsigned int min)
{
	if (modifier < 1)
		return base;

	if (modifier < base)
		val /= modifier;
	else
		val -= modifier;

	return max(val, min);
}

#define MSR_IA32_CR_PAT_DEFAULT  0x0007040600070406ULL

static inline void kvm_clear_exception_queue(struct kvm_vcpu *vcpu)
{
	vcpu->arch.exception.pending = false;
	vcpu->arch.exception.injected = false;
}

static inline void kvm_queue_interrupt(struct kvm_vcpu *vcpu, u8 vector,
	bool soft)
{
	vcpu->arch.interrupt.injected = true;
	vcpu->arch.interrupt.soft = soft;
	vcpu->arch.interrupt.nr = vector;
}

static inline void kvm_clear_interrupt_queue(struct kvm_vcpu *vcpu)
{
	vcpu->arch.interrupt.injected = false;
}

static inline bool kvm_event_needs_reinjection(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.exception.injected || vcpu->arch.interrupt.injected ||
		vcpu->arch.nmi_injected;
}

static inline bool kvm_exception_is_soft(unsigned int nr)
{
	return (nr == BP_VECTOR) || (nr == OF_VECTOR);
}

static inline bool is_protmode(struct kvm_vcpu *vcpu)
{
	return kvm_read_cr0_bits(vcpu, X86_CR0_PE);
}

static inline int is_long_mode(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_X86_64
	return vcpu->arch.efer & EFER_LMA;
#else
	return 0;
#endif
}

static inline bool is_64_bit_mode(struct kvm_vcpu *vcpu)
{
	int cs_db, cs_l;

	if (!is_long_mode(vcpu))
		return false;
	kvm_x86_ops.get_cs_db_l_bits(vcpu, &cs_db, &cs_l);
	return cs_l;
}

static inline bool is_la57_mode(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_X86_64
	return (vcpu->arch.efer & EFER_LMA) &&
		 kvm_read_cr4_bits(vcpu, X86_CR4_LA57);
#else
	return 0;
#endif
}

static inline bool x86_exception_has_error_code(unsigned int vector)
{
	static u32 exception_has_error_code = BIT(DF_VECTOR) | BIT(TS_VECTOR) |
			BIT(NP_VECTOR) | BIT(SS_VECTOR) | BIT(GP_VECTOR) |
			BIT(PF_VECTOR) | BIT(AC_VECTOR);

	return (1U << vector) & exception_has_error_code;
}

static inline bool mmu_is_nested(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.walk_mmu == &vcpu->arch.nested_mmu;
}

static inline void kvm_vcpu_flush_tlb_current(struct kvm_vcpu *vcpu)
{
	++vcpu->stat.tlb_flush;
	kvm_x86_ops.tlb_flush_current(vcpu);
}

static inline int is_pae(struct kvm_vcpu *vcpu)
{
	return kvm_read_cr4_bits(vcpu, X86_CR4_PAE);
}

static inline int is_pse(struct kvm_vcpu *vcpu)
{
	return kvm_read_cr4_bits(vcpu, X86_CR4_PSE);
}

static inline int is_paging(struct kvm_vcpu *vcpu)
{
	return likely(kvm_read_cr0_bits(vcpu, X86_CR0_PG));
}

static inline bool is_pae_paging(struct kvm_vcpu *vcpu)
{
	return !is_long_mode(vcpu) && is_pae(vcpu) && is_paging(vcpu);
}

static inline u8 vcpu_virt_addr_bits(struct kvm_vcpu *vcpu)
{
	return kvm_read_cr4_bits(vcpu, X86_CR4_LA57) ? 57 : 48;
}

static inline bool is_noncanonical_address(u64 la, struct kvm_vcpu *vcpu)
{
	return !__is_canonical_address(la, vcpu_virt_addr_bits(vcpu));
}

static inline void vcpu_cache_mmio_info(struct kvm_vcpu *vcpu,
					gva_t gva, gfn_t gfn, unsigned access)
{
	u64 gen = kvm_memslots(vcpu->kvm)->generation;

	if (unlikely(gen & KVM_MEMSLOT_GEN_UPDATE_IN_PROGRESS))
		return;

	/*
	 * If this is a shadow nested page table, the "GVA" is
	 * actually a nGPA.
	 */
	vcpu->arch.mmio_gva = mmu_is_nested(vcpu) ? 0 : gva & PAGE_MASK;
	vcpu->arch.mmio_access = access;
	vcpu->arch.mmio_gfn = gfn;
	vcpu->arch.mmio_gen = gen;
}

static inline bool vcpu_match_mmio_gen(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmio_gen == kvm_memslots(vcpu->kvm)->generation;
}

/*
 * Clear the mmio cache info for the given gva. If gva is MMIO_GVA_ANY, we
 * clear all mmio cache info.
 */
#define MMIO_GVA_ANY (~(gva_t)0)

static inline void vcpu_clear_mmio_info(struct kvm_vcpu *vcpu, gva_t gva)
{
	if (gva != MMIO_GVA_ANY && vcpu->arch.mmio_gva != (gva & PAGE_MASK))
		return;

	vcpu->arch.mmio_gva = 0;
}

static inline bool vcpu_match_mmio_gva(struct kvm_vcpu *vcpu, unsigned long gva)
{
	if (vcpu_match_mmio_gen(vcpu) && vcpu->arch.mmio_gva &&
	      vcpu->arch.mmio_gva == (gva & PAGE_MASK))
		return true;

	return false;
}

static inline bool vcpu_match_mmio_gpa(struct kvm_vcpu *vcpu, gpa_t gpa)
{
	if (vcpu_match_mmio_gen(vcpu) && vcpu->arch.mmio_gfn &&
	      vcpu->arch.mmio_gfn == gpa >> PAGE_SHIFT)
		return true;

	return false;
}

static inline unsigned long kvm_register_readl(struct kvm_vcpu *vcpu, int reg)
{
	unsigned long val = kvm_register_read(vcpu, reg);

	return is_64_bit_mode(vcpu) ? val : (u32)val;
}

static inline void kvm_register_writel(struct kvm_vcpu *vcpu,
				       int reg, unsigned long val)
{
	if (!is_64_bit_mode(vcpu))
		val = (u32)val;
	return kvm_register_write(vcpu, reg, val);
}

static inline bool kvm_check_has_quirk(struct kvm *kvm, u64 quirk)
{
	return !(kvm->arch.disabled_quirks & quirk);
}

static inline bool kvm_vcpu_latch_init(struct kvm_vcpu *vcpu)
{
	return is_smm(vcpu) || kvm_x86_ops.apic_init_signal_blocked(vcpu);
}

void kvm_inject_realmode_interrupt(struct kvm_vcpu *vcpu, int irq, int inc_eip);

void kvm_write_tsc(struct kvm_vcpu *vcpu, struct msr_data *msr);
u64 get_kvmclock_ns(struct kvm *kvm);

int kvm_read_guest_virt(struct kvm_vcpu *vcpu,
	gva_t addr, void *val, unsigned int bytes,
	struct x86_exception *exception);

int kvm_write_guest_virt_system(struct kvm_vcpu *vcpu,
	gva_t addr, void *val, unsigned int bytes,
	struct x86_exception *exception);

int handle_ud(struct kvm_vcpu *vcpu);

void kvm_deliver_exception_payload(struct kvm_vcpu *vcpu);

void kvm_vcpu_mtrr_init(struct kvm_vcpu *vcpu);
u8 kvm_mtrr_get_guest_memory_type(struct kvm_vcpu *vcpu, gfn_t gfn);
bool kvm_mtrr_valid(struct kvm_vcpu *vcpu, u32 msr, u64 data);
int kvm_mtrr_set_msr(struct kvm_vcpu *vcpu, u32 msr, u64 data);
int kvm_mtrr_get_msr(struct kvm_vcpu *vcpu, u32 msr, u64 *pdata);
bool kvm_mtrr_check_gfn_range_consistency(struct kvm_vcpu *vcpu, gfn_t gfn,
					  int page_num);
bool kvm_vector_hashing_enabled(void);
void kvm_fixup_and_inject_pf_error(struct kvm_vcpu *vcpu, gva_t gva, u16 error_code);
int x86_decode_emulated_instruction(struct kvm_vcpu *vcpu, int emulation_type,
				    void *insn, int insn_len);
int x86_emulate_instruction(struct kvm_vcpu *vcpu, gpa_t cr2_or_gpa,
			    int emulation_type, void *insn, int insn_len);
fastpath_t handle_fastpath_set_msr_irqoff(struct kvm_vcpu *vcpu);

extern u64 host_xcr0;
extern u64 supported_xcr0;
extern u64 supported_xss;

static inline bool kvm_mpx_supported(void)
{
	return (supported_xcr0 & (XFEATURE_MASK_BNDREGS | XFEATURE_MASK_BNDCSR))
		== (XFEATURE_MASK_BNDREGS | XFEATURE_MASK_BNDCSR);
}

extern unsigned int min_timer_period_us;

extern bool enable_vmware_backdoor;

extern int pi_inject_timer;

extern struct static_key kvm_no_apic_vcpu;

extern bool report_ignored_msrs;

static inline u64 nsec_to_cycles(struct kvm_vcpu *vcpu, u64 nsec)
{
	return pvclock_scale_delta(nsec, vcpu->arch.virtual_tsc_mult,
				   vcpu->arch.virtual_tsc_shift);
}

/* Same "calling convention" as do_div:
 * - divide (n << 32) by base
 * - put result in n
 * - return remainder
 */
#define do_shl32_div32(n, base)					\
	({							\
	    u32 __quot, __rem;					\
	    asm("divl %2" : "=a" (__quot), "=d" (__rem)		\
			: "rm" (base), "0" (0), "1" ((u32) n));	\
	    n = __quot;						\
	    __rem;						\
	 })

static inline bool kvm_mwait_in_guest(struct kvm *kvm)
{
	return kvm->arch.mwait_in_guest;
}

static inline bool kvm_hlt_in_guest(struct kvm *kvm)
{
	return kvm->arch.hlt_in_guest;
}

static inline bool kvm_pause_in_guest(struct kvm *kvm)
{
	return kvm->arch.pause_in_guest;
}

static inline bool kvm_cstate_in_guest(struct kvm *kvm)
{
	return kvm->arch.cstate_in_guest;
}

DECLARE_PER_CPU(struct kvm_vcpu *, current_vcpu);

static inline bool kvm_notify_vmexit_enabled(struct kvm *kvm)
{
	return kvm->arch.notify_vmexit_flags & KVM_X86_NOTIFY_VMEXIT_ENABLED;
}

static inline void kvm_before_interrupt(struct kvm_vcpu *vcpu)
{
	__this_cpu_write(current_vcpu, vcpu);
}

static inline void kvm_after_interrupt(struct kvm_vcpu *vcpu)
{
	__this_cpu_write(current_vcpu, NULL);
}


static inline bool kvm_pat_valid(u64 data)
{
	if (data & 0xF8F8F8F8F8F8F8F8ull)
		return false;
	/* 0, 1, 4, 5, 6, 7 are valid values.  */
	return (data | ((data & 0x0202020202020202ull) << 1)) == data;
}

static inline bool kvm_dr7_valid(u64 data)
{
	/* Bits [63:32] are reserved */
	return !(data >> 32);
}
static inline bool kvm_dr6_valid(u64 data)
{
	/* Bits [63:32] are reserved */
	return !(data >> 32);
}

void kvm_load_guest_xsave_state(struct kvm_vcpu *vcpu);
void kvm_load_host_xsave_state(struct kvm_vcpu *vcpu);
int kvm_spec_ctrl_test_value(u64 value);
bool kvm_is_valid_cr4(struct kvm_vcpu *vcpu, unsigned long cr4);
bool kvm_vcpu_exit_request(struct kvm_vcpu *vcpu);
int kvm_handle_memory_failure(struct kvm_vcpu *vcpu, int r,
			      struct x86_exception *e);
int kvm_handle_invpcid(struct kvm_vcpu *vcpu, unsigned long type, gva_t gva);
bool kvm_msr_allowed(struct kvm_vcpu *vcpu, u32 index, u32 type);

/*
 * Internal error codes that are used to indicate that MSR emulation encountered
 * an error that should result in #GP in the guest, unless userspace
 * handles it.
 */
#define  KVM_MSR_RET_INVALID	2	/* in-kernel MSR emulation #GP condition */
#define  KVM_MSR_RET_FILTERED	3	/* #GP due to userspace MSR filter */

#define __cr4_reserved_bits(__cpu_has, __c)             \
({                                                      \
	u64 __reserved_bits = CR4_RESERVED_BITS;        \
                                                        \
	if (!__cpu_has(__c, X86_FEATURE_XSAVE))         \
		__reserved_bits |= X86_CR4_OSXSAVE;     \
	if (!__cpu_has(__c, X86_FEATURE_SMEP))          \
		__reserved_bits |= X86_CR4_SMEP;        \
	if (!__cpu_has(__c, X86_FEATURE_SMAP))          \
		__reserved_bits |= X86_CR4_SMAP;        \
	if (!__cpu_has(__c, X86_FEATURE_FSGSBASE))      \
		__reserved_bits |= X86_CR4_FSGSBASE;    \
	if (!__cpu_has(__c, X86_FEATURE_PKU))           \
		__reserved_bits |= X86_CR4_PKE;         \
	if (!__cpu_has(__c, X86_FEATURE_LA57))          \
		__reserved_bits |= X86_CR4_LA57;        \
	if (!__cpu_has(__c, X86_FEATURE_UMIP))          \
		__reserved_bits |= X86_CR4_UMIP;        \
	if (!__cpu_has(__c, X86_FEATURE_VMX))           \
		__reserved_bits |= X86_CR4_VMXE;        \
	if (!__cpu_has(__c, X86_FEATURE_PCID))          \
		__reserved_bits |= X86_CR4_PCIDE;       \
	__reserved_bits;                                \
})

#endif
