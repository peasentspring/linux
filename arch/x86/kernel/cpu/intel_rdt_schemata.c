/*
 * Resource Director Technology(RDT)
 * - Cache Allocation code.
 *
 * Copyright (C) 2016 Intel Corporation
 *
 * Authors:
 *    Fenghua Yu <fenghua.yu@intel.com>
 *    Tony Luck <tony.luck@intel.com>
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

#include <linux/kernfs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <asm/intel_rdt.h>

/*
 * Check whether a cache bit mask is valid. The SDM says:
 *	Please note that all (and only) contiguous '1' combinations
 *	are allowed (e.g. FFFFH, 0FF0H, 003CH, etc.).
 * Additionally Haswell requires at least two bits set.
 */
static bool cbm_validate(unsigned long var, struct rdt_resource *r)
{
	unsigned long first_bit, zero_bit;

	if (var == 0 || var > r->max_cbm)
		return false;

	first_bit = find_first_bit(&var, r->cbm_len);
	zero_bit = find_next_zero_bit(&var, r->cbm_len, first_bit);

	if (find_next_bit(&var, r->cbm_len, zero_bit) < r->cbm_len)
		return false;

	if ((zero_bit - first_bit) < r->min_cbm_bits)
		return false;
	return true;
}

/*
 * Read one cache bit mask (hex). Check that it is valid for the current
 * resource type.
 */
static int parse_cbm_token(char *tok, struct rdt_resource *r)
{
	unsigned long data;
	int ret;

	ret = kstrtoul(tok, 16, &data);
	if (ret)
		return ret;
	if (!cbm_validate(data, r))
		return -EINVAL;
	r->tmp_cbms[r->num_cbms++] = data;
	return 0;
}

/*
 * If code/data prioritization is enabled for this resource we need
 * two bit masks separated by a ",". Otherwise a single bit mask.
 */
static int parse_cbm(char *buf, struct rdt_resource *r)
{
	char *cbm1 = buf;
	int ret;

	if (r->cdp_enabled)
		cbm1 = strsep(&buf, ",");
	if (!cbm1 || !buf)
		return 1;
	ret = parse_cbm_token(cbm1, r);
	if (ret)
		return ret;
	if (r->cdp_enabled)
		return parse_cbm_token(buf, r);
	return 0;
}

/*
 * For each domain in this resource we expect to find a series of:
 *	id=mask[,mask]
 * separated by ";". The "id" is in decimal, and must appear in the
 * right order.
 */
static int parse_line(char *line, struct rdt_resource *r)
{
	struct list_head *l;
	struct rdt_domain *d;
	char *dom = NULL, *id;
	unsigned long dom_id;

	list_for_each(l, &r->domains) {
		d = list_entry(l, struct rdt_domain, list);
		dom = strsep(&line, ";");
		if (!dom)
			return -EINVAL;
		id = strsep(&dom, "=");
		if (kstrtoul(id, 10, &dom_id) || dom_id != d->id)
			return -EINVAL;
		if (parse_cbm(dom, r))
			return -EINVAL;
	}

	/* Any garbage at the end of the line? */
	if (line && line[0])
		return -EINVAL;
	return 0;
}

static void update_domains(struct rdt_resource *r, int closid)
{
	int idx = 0;
	struct list_head *l;
	struct rdt_domain *d;
	struct msr_param msr_param;
	struct cpumask cpu_mask;

	cpumask_clear(&cpu_mask);
	msr_param.low = closid << r->cdp_enabled;
	msr_param.high = msr_param.low + 1 + r->cdp_enabled;
	msr_param.res = r;

	list_for_each(l, &r->domains) {
		d = list_entry(l, struct rdt_domain, list);
		cpumask_set_cpu(cpumask_any(&d->cpu_mask), &cpu_mask);
		d->cbm[msr_param.low] = r->tmp_cbms[idx++];
		if (r->cdp_enabled)
			d->cbm[msr_param.low + 1] = r->tmp_cbms[idx++];
	}
	smp_call_function_many(&cpu_mask, rdt_cbm_update, &msr_param, 1);
}

ssize_t rdtgroup_schemata_write(struct kernfs_open_file *of,
				char *buf, size_t nbytes, loff_t off)
{
	char *tok, *resname;
	struct rdtgroup *rdtgrp;
	struct rdt_resource *r;
	int closid, ret = 0;
	u32 *l3_cbms = NULL;

	/* Legal input requires a trailing newline */
	if (nbytes == 0 || buf[nbytes - 1] != '\n')
		return -EINVAL;
	buf[nbytes - 1] = '\0';

	rdtgrp = rdtgroup_kn_lock_live(of->kn);
	if (!rdtgrp) {
		rdtgroup_kn_unlock(of->kn);
		return -ENOENT;
	}

	closid = rdtgrp->closid;

	/* get scratch space to save all the masks while we validate input */
	for_each_rdt_resource(r) {
		r->tmp_cbms = kcalloc(r->num_domains << r->cdp_enabled,
				      sizeof(*l3_cbms), GFP_KERNEL);
		if (!r->tmp_cbms) {
			ret = -ENOMEM;
			goto fail;
		}
		r->num_cbms = 0;
	}

	while ((tok = strsep(&buf, "\n")) != NULL) {
		resname = strsep(&tok, ":");
		if (!tok) {
			ret = -EINVAL;
			goto fail;
		}
		for_each_rdt_resource(r) {
			if (!strcmp(resname, r->name) &&
			    closid < r->num_closid) {
				ret = parse_line(tok, r);
				if (ret)
					goto fail;
				break;
			}
		}
		if (!r->name) {
			ret = -EINVAL;
			goto fail;
		}
	}

	/* Did the parser find all the masks we need? */
	for_each_rdt_resource(r) {
		if (r->num_cbms != r->num_domains << r->cdp_enabled) {
			ret = -EINVAL;
			goto fail;
		}
	}

	for_each_rdt_resource(r)
		update_domains(r, closid);

fail:
	rdtgroup_kn_unlock(of->kn);
	for_each_rdt_resource(r) {
		kfree(r->tmp_cbms);
		r->tmp_cbms = NULL;
	}
	return ret ?: nbytes;
}

static void show_doms(struct seq_file *s, struct rdt_resource *r, int closid)
{
	struct list_head *l;
	struct rdt_domain *dom;
	int idx = closid << r->cdp_enabled;
	bool sep = false;

	seq_printf(s, "%s:", r->name);
	list_for_each(l, &r->domains) {
		dom = list_entry(l, struct rdt_domain, list);
		if (sep)
			seq_puts(s, ";");
		seq_printf(s, "%d=%x", dom->id, dom->cbm[idx]);
		if (r->cdp_enabled)
			seq_printf(s, ",%x", dom->cbm[idx + 1]);
		sep = true;
	}
	seq_puts(s, "\n");
}

int rdtgroup_schemata_show(struct kernfs_open_file *of,
			   struct seq_file *s, void *v)
{
	struct rdtgroup *rdtgrp;
	struct rdt_resource *r;
	int closid, ret = 0;

	rdtgrp = rdtgroup_kn_lock_live(of->kn);
	if (rdtgrp) {
		closid = rdtgrp->closid;
		for_each_rdt_resource(r)
			if (closid < r->num_closid)
				show_doms(s, r, closid);
	} else {
		ret = -ENOENT;
	}
	rdtgroup_kn_unlock(of->kn);
	return ret;
}
