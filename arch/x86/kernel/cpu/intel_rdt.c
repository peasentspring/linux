/*
 * Resource Director Technology(RDT)
 * - Cache Allocation code.
 *
 * Copyright (C) 2014 Intel Corporation
 *
 * 2015-05-25 Written by
 *    Vikas Shivappa <vikas.shivappa@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * More information about RDT be found in the Intel (R) x86 Architecture
 * Software Developer Manual June 2015, volume 3, section 17.15.
 */
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/cpu.h>
#include <linux/sched.h>
#include <asm/pqr_common.h>
#include <asm/intel_rdt.h>

/*
 * cctable maintains 1:1 mapping between CLOSid and cache bitmask.
 */
static struct clos_cbm_table *cctable;
/*
 * closid availability bit map.
 */
unsigned long *closmap;
/*
 * Minimum bits required in Cache bitmask.
 */
unsigned int min_bitmask_len = 1;
/*
 * Mask of CPUs for writing CBM values. We only need one CPU per-socket.
 */
static cpumask_t rdt_cpumask;
/*
 * Temporary cpumask used during hot cpu notificaiton handling. The usage
 * is serialized by hot cpu locks.
 */
static cpumask_t tmp_cpumask;
static DEFINE_MUTEX(rdtgroup_mutex);
struct static_key __read_mostly rdt_enable_key = STATIC_KEY_INIT_FALSE;

struct rdt_remote_data {
	int msr;
	u64 val;
};

/*
 * cache_alloc_hsw_probe() - Have to probe for Intel haswell server CPUs
 * as it does not have CPUID enumeration support for Cache allocation.
 *
 * Probes by writing to the high 32 bits(CLOSid) of the IA32_PQR_MSR and
 * testing if the bits stick. Max CLOSids is always 4 and max cbm length
 * is always 20 on hsw server parts. The minimum cache bitmask length
 * allowed for HSW server is always 2 bits. Hardcode all of them.
 */
static inline bool cache_alloc_hsw_probe(void)
{
	u32 l, h_old, h_new, h_tmp;

	if (rdmsr_safe(MSR_IA32_PQR_ASSOC, &l, &h_old))
		return false;

	/*
	 * Default value is always 0 if feature is present.
	 */
	h_tmp = h_old ^ 0x1U;
	if (wrmsr_safe(MSR_IA32_PQR_ASSOC, l, h_tmp) ||
	    rdmsr_safe(MSR_IA32_PQR_ASSOC, &l, &h_new))
		return false;

	if (h_tmp != h_new)
		return false;

	wrmsr_safe(MSR_IA32_PQR_ASSOC, l, h_old);

	boot_cpu_data.x86_cache_max_closid = 4;
	boot_cpu_data.x86_cache_max_cbm_len = 20;
	min_bitmask_len = 2;

	return true;
}

void __intel_rdt_sched_in(void *dummy)
{
	struct intel_pqr_state *state = this_cpu_ptr(&pqr_state);

	/*
	 * Currently closid is always 0. When  user interface is added,
	 * closid will come from user interface.
	 */
	if (state->closid == 0)
		return;

	wrmsr(MSR_IA32_PQR_ASSOC, state->rmid, 0);
	state->closid = 0;
}

static inline void closid_get(u32 closid)
{
	struct clos_cbm_table *cct = &cctable[closid];

	lockdep_assert_held(&rdtgroup_mutex);

	cct->clos_refcnt++;
}

static int closid_alloc(u32 *closid)
{
	u32 maxid;
	u32 id;

	lockdep_assert_held(&rdtgroup_mutex);

	maxid = boot_cpu_data.x86_cache_max_closid;
	id = find_first_zero_bit(closmap, maxid);
	if (id == maxid)
		return -ENOSPC;

	set_bit(id, closmap);
	closid_get(id);
	*closid = id;

	return 0;
}

static inline void closid_free(u32 closid)
{
	clear_bit(closid, closmap);
	cctable[closid].cbm = 0;
}

static void closid_put(u32 closid)
{
	struct clos_cbm_table *cct = &cctable[closid];

	lockdep_assert_held(&rdtgroup_mutex);
	if (WARN_ON(!cct->clos_refcnt))
		return;

	if (!--cct->clos_refcnt)
		closid_free(closid);
}

static void msr_cpu_update(void *arg)
{
	struct rdt_remote_data *info = arg;

	wrmsrl(info->msr, info->val);
}

/*
 * msr_update_all() - Update the msr for all packages.
 */
static inline void msr_update_all(int msr, u64 val)
{
	struct rdt_remote_data info;

	info.msr = msr;
	info.val = val;
	on_each_cpu_mask(&rdt_cpumask, msr_cpu_update, &info, 1);
}

/*
 * Set only one cpu in cpumask in all cpus that share the same cache.
 */
static inline bool rdt_cpumask_update(int cpu)
{
	cpumask_and(&tmp_cpumask, &rdt_cpumask, topology_core_cpumask(cpu));
	if (cpumask_empty(&tmp_cpumask)) {
		cpumask_set_cpu(cpu, &rdt_cpumask);
		return true;
	}

	return false;
}

/*
 * cbm_update_msrs() - Updates all the existing IA32_L3_MASK_n MSRs
 * which are one per CLOSid on the current package.
 */
static void cbm_update_msrs(void *dummy)
{
	int maxid = boot_cpu_data.x86_cache_max_closid;
	struct rdt_remote_data info;
	unsigned int i;

	for (i = 0; i < maxid; i++) {
		if (cctable[i].clos_refcnt) {
			info.msr = CBM_FROM_INDEX(i);
			info.val = cctable[i].cbm;
			msr_cpu_update(&info);
		}
	}
}

static int intel_rdt_online_cpu(unsigned int cpu)
{
	struct intel_pqr_state *state = &per_cpu(pqr_state, cpu);

	state->closid = 0;
	mutex_lock(&rdtgroup_mutex);
	/* The cpu is set in root rdtgroup after online. */
	cpumask_set_cpu(cpu, &root_rdtgrp->cpu_mask);
	per_cpu(cpu_rdtgroup, cpu) = root_rdtgrp;
	/*
	 * If the cpu is first time found and set in its siblings that
	 * share the same cache, update the CBM MSRs for the cache.
	 */
	if (rdt_cpumask_update(cpu))
		smp_call_function_single(cpu, cbm_update_msrs, NULL, 1);
	mutex_unlock(&rdtgroup_mutex);
}

static int clear_rdtgroup_cpumask(unsigned int cpu)
{
	struct list_head *l;
	struct rdtgroup *r;

	list_for_each(l, &rdtgroup_lists) {
		r = list_entry(l, struct rdtgroup, rdtgroup_list);
		if (cpumask_test_cpu(cpu, &r->cpu_mask)) {
			cpumask_clear_cpu(cpu, &r->cpu_mask);
			return 0;
		}
	}

	return -EINVAL;
}

static int intel_rdt_offline_cpu(unsigned int cpu)
{
	int i;

	mutex_lock(&rdtgroup_mutex);
	if (!cpumask_test_and_clear_cpu(cpu, &rdt_cpumask)) {
		mutex_unlock(&rdtgroup_mutex);
		return;
	}

	cpumask_and(&tmp_cpumask, topology_core_cpumask(cpu), cpu_online_mask);
	cpumask_clear_cpu(cpu, &tmp_cpumask);
	i = cpumask_any(&tmp_cpumask);

	if (i < nr_cpu_ids)
		cpumask_set_cpu(i, &rdt_cpumask);

	clear_rdtgroup_cpumask(cpu);
	mutex_unlock(&rdtgroup_mutex);
}

static int __init intel_rdt_late_init(void)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;
	u32 maxid;
	int err = 0, size, i;

	maxid = c->x86_cache_max_closid;

	size = maxid * sizeof(struct clos_cbm_table);
	cctable = kzalloc(size, GFP_KERNEL);
	if (!cctable) {
		err = -ENOMEM;
		goto out_err;
	}

	size = BITS_TO_LONGS(maxid) * sizeof(long);
	closmap = kzalloc(size, GFP_KERNEL);
	if (!closmap) {
		kfree(cctable);
		err = -ENOMEM;
		goto out_err;
	}

	for_each_online_cpu(i)
		rdt_cpumask_update(i);

	ret = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN,
				"AP_INTEL_RDT_ONLINE",
				intel_rdt_online_cpu, intel_rdt_offline_cpu);
	if (err < 0)
		goto out_err;

	pr_info("Intel cache allocation enabled\n");
out_err:

	return err;
}

late_initcall(intel_rdt_late_init);
