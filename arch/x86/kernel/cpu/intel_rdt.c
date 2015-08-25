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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/slab.h>
#include <linux/err.h>
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
 * Mask of CPUs for writing CBM values. We only need one CPU per-socket.
 */
static cpumask_t rdt_cpumask;
/*
 * Temporary cpumask used during hot cpu notificaiton handling. The usage
 * is serialized by hot cpu locks.
 */
static cpumask_t tmp_cpumask;
static DEFINE_MUTEX(rdtgroup_mutex);

struct rdt_remote_data {
	int msr;
	u64 val;
};

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

static inline bool rdt_cpumask_update(int cpu)
{
	cpumask_and(&tmp_cpumask, &rdt_cpumask, topology_core_cpumask(cpu));
	if (cpumask_empty(&tmp_cpumask)) {
		cpumask_set_cpu(cpu, &rdt_cpumask);
		return true;
	}

	return false;
}

static int __init intel_rdt_late_init(void)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;
	u32 maxid;
	int err = 0, size, i;

	if (!cpu_has(c, X86_FEATURE_CAT_L3))
		return -ENODEV;

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
	pr_info("Intel cache allocation enabled\n");
out_err:

	return err;
}

late_initcall(intel_rdt_late_init);
