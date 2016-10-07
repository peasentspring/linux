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
	if (wrmsr_safe(MSR_IA32_PQR_ASSOC, l, h_tmp))
		return false;
	rdmsr(MSR_IA32_PQR_ASSOC, l, h_new);

	if (h_tmp != h_new)
		return false;

	wrmsr(MSR_IA32_PQR_ASSOC, l, h_old);

	return true;
}

static inline bool get_rdt_resources(struct cpuinfo_x86 *c)
{
	bool ret = false;

	if (c->x86_vendor == X86_VENDOR_INTEL && c->x86 == 6 &&
	    c->x86_model == INTEL_FAM6_HASWELL_X)
		return cache_alloc_hsw_probe();

	if (!cpu_has(c, X86_FEATURE_RDT_A))
		return false;
	if (cpu_has(c, X86_FEATURE_CAT_L3))
		ret = true;

	return ret;
}

static int __init intel_rdt_late_init(void)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;

	if (!get_rdt_resources(c))
		return -ENODEV;

	pr_info("Intel cache allocation detected\n");
	if (cpu_has(c, X86_FEATURE_CDP_L3))
		pr_info("Intel code data prioritization detected\n");

	return 0;
}

late_initcall(intel_rdt_late_init);
