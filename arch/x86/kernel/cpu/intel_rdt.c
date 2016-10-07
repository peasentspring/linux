/*
 * Resource Director Technology(RDT)
 * - Cache Allocation code.
 *
 * Copyright (C) 2016 Intel Corporation
 *
 * Authors:
 *    Fenghua Yu <fenghua.yu@intel.com>
 *    Tony Luck <tony.luck@intel.com>
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
 * Software Developer Manual June 2016, volume 3, section 17.17.
 */

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/slab.h>
#include <linux/err.h>
#include <asm/intel_rdt_common.h>
#include <asm/intel-family.h>
#include <asm/intel_rdt.h>

int rdt_max_closid;

#define domain_init(name) LIST_HEAD_INIT(rdt_resources_all[name].domains)

struct rdt_resource rdt_resources_all[] = {
	{
		.name		= "L3",
		.domains	= domain_init(RDT_RESOURCE_L3),
		.msr_base	= IA32_L3_CBM_BASE,
		.min_cbm_bits	= 1,
		.cache_level	= 3
	},
	{
		/* NULL terminated */
	}
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
	struct rdt_resource *r = &rdt_resources_all[RDT_RESOURCE_L3];

	if (rdmsr_safe(MSR_IA32_PQR_ASSOC, &l, &h_old))
		return false;

	/*
	 * Default value is always 0 if feature is present.
	 */
	h_tmp = h_old ^ 0x1U;
	if (wrmsr_safe(MSR_IA32_PQR_ASSOC, l, h_tmp))
		return false;
	rdmsr(MSR_IA32_PQR_ASSOC, l, h_new);

	if (h_tmp != h_new)
		return false;

	wrmsr(MSR_IA32_PQR_ASSOC, l, h_old);

	r->max_closid = 4;
	r->num_closid = r->max_closid;
	r->cbm_len = 20;
	r->max_cbm = BIT_MASK(20) - 1;
	r->min_cbm_bits = 2;
	r->enabled = true;

	return true;
}

static inline bool get_rdt_resources(struct cpuinfo_x86 *c)
{
	struct rdt_resource *r;
	bool ret = false;

	if (c->x86_vendor == X86_VENDOR_INTEL && c->x86 == 6 &&
	    c->x86_model == INTEL_FAM6_HASWELL_X)
		return cache_alloc_hsw_probe();

	if (!cpu_has(c, X86_FEATURE_RDT_A))
		return false;
	if (cpu_has(c, X86_FEATURE_CAT_L3)) {
		union cpuid_0x10_1_eax eax;
		union cpuid_0x10_1_edx edx;
		u32 ebx, ecx;

		r = &rdt_resources_all[RDT_RESOURCE_L3];
		cpuid_count(0x00000010, 1, &eax.full, &ebx, &ecx, &edx.full);
		r->max_closid = edx.split.cos_max + 1;
		r->num_closid = r->max_closid;
		r->cbm_len = eax.split.cbm_len + 1;
		r->max_cbm = BIT_MASK(eax.split.cbm_len + 1) - 1;
		if (cpu_has(c, X86_FEATURE_CDP_L3))
			r->cdp_capable = true;
		r->enabled = true;

		ret = true;
	}

	return ret;
}

static int __init intel_rdt_late_init(void)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;
	struct rdt_resource *r;

	if (!get_rdt_resources(c))
		return -ENODEV;

	for_each_rdt_resource(r)
		rdt_max_closid = max(rdt_max_closid, r->max_closid);

	for_each_rdt_resource(r)
		pr_info("Intel %s allocation %s detected\n", r->name,
			r->cdp_capable ? " (with CDP)" : "");

	return 0;
}

late_initcall(intel_rdt_late_init);
