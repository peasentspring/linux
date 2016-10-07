/*
 * User interface for Resource Alloction in Resource Director Technology(RDT)
 *
 * Copyright (C) 2016 Intel Corporation
 *
 * Author: Fenghua Yu <fenghua.yu@intel.com>
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
 * Software Developer Manual.
 */

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/sysfs.h>
#include <linux/kernfs.h>
#include <linux/slab.h>

#include <uapi/linux/magic.h>

#include <asm/intel_rdt.h>

DEFINE_STATIC_KEY_FALSE(rdt_enable_key);
struct kernfs_root *rdt_root;
struct rdtgroup rdtgroup_default;
LIST_HEAD(rdt_all_groups);

static void l3_qos_cfg_update(void *arg)
{
	struct rdt_resource *r = arg;

	wrmsrl(IA32_L3_QOS_CFG, r->cdp_enabled);
}

static void set_l3_qos_cfg(struct rdt_resource *r)
{
	struct list_head *l;
	struct rdt_domain *d;
	struct cpumask cpu_mask;

	cpumask_clear(&cpu_mask);
	list_for_each(l, &r->domains) {
		d = list_entry(l, struct rdt_domain, list);
		cpumask_set_cpu(cpumask_any(&d->cpu_mask), &cpu_mask);
	}
	smp_call_function_many(&cpu_mask, l3_qos_cfg_update, r, 1);
}

static int parse_rdtgroupfs_options(char *data, struct rdt_resource *r)
{
	char *token, *o = data;

	while ((token = strsep(&o, ",")) != NULL) {
		if (!*token)
			return -EINVAL;

		if (!strcmp(token, "cdp"))
			if (r->enabled && r->cdp_capable)
				r->cdp_enabled = true;
	}

	return 0;
}

static struct dentry *rdt_mount(struct file_system_type *fs_type,
				int flags, const char *unused_dev_name,
				void *data)
{
	struct dentry *dentry;
	int ret;
	bool new_sb;
	struct rdt_resource *r = &rdt_resources_all[RDT_RESOURCE_L3];

	mutex_lock(&rdtgroup_mutex);
	/*
	 * resctrl file system can only be mounted once.
	 */
	if (static_branch_unlikely(&rdt_enable_key)) {
		dentry = ERR_PTR(-EBUSY);
		goto out;
	}

	r->cdp_enabled = false;
	ret = parse_rdtgroupfs_options(data, r);
	if (ret) {
		dentry = ERR_PTR(ret);
		goto out;
	}
	if (r->cdp_enabled)
		r->num_closid = r->max_closid / 2;
	else
		r->num_closid = r->max_closid;

	/* Recompute rdt_max_closid because CDP may have changed things. */
	rdt_max_closid = 0;
	for_each_rdt_resource(r)
		rdt_max_closid = max(rdt_max_closid, r->num_closid);
	if (rdt_max_closid > 32)
		rdt_max_closid = 32;

	dentry = kernfs_mount(fs_type, flags, rdt_root,
			      RDTGROUP_SUPER_MAGIC, &new_sb);
	if (IS_ERR(dentry))
		goto out;
	if (!new_sb) {
		dentry = ERR_PTR(-EINVAL);
		goto out;
	}
	r = &rdt_resources_all[RDT_RESOURCE_L3];
	if (r->cdp_capable)
		set_l3_qos_cfg(r);
	static_branch_enable(&rdt_enable_key);

out:
	mutex_unlock(&rdtgroup_mutex);

	return dentry;
}

static void reset_all_cbms(struct rdt_resource *r)
{
	struct list_head *l;
	struct rdt_domain *d;
	struct msr_param msr_param;
	struct cpumask cpu_mask;
	int i;

	cpumask_clear(&cpu_mask);
	msr_param.res = r;
	msr_param.low = 0;
	msr_param.high = r->max_closid;

	list_for_each(l, &r->domains) {
		d = list_entry(l, struct rdt_domain, list);
		cpumask_set_cpu(cpumask_any(&d->cpu_mask), &cpu_mask);

		for (i = 0; i < r->max_closid; i++)
			d->cbm[i] = r->max_cbm;
	}
	smp_call_function_many(&cpu_mask, rdt_cbm_update, &msr_param, 1);
}

static void rdt_kill_sb(struct super_block *sb)
{
	struct rdt_resource *r;

	mutex_lock(&rdtgroup_mutex);

	/*Put everything back to default values. */
	for_each_rdt_resource(r)
		reset_all_cbms(r);
	r = &rdt_resources_all[RDT_RESOURCE_L3];
	if (r->cdp_capable) {
		r->cdp_enabled = 0;
		set_l3_qos_cfg(r);
	}

	static_branch_disable(&rdt_enable_key);
	kernfs_kill_sb(sb);
	mutex_unlock(&rdtgroup_mutex);
}

static struct file_system_type rdt_fs_type = {
	.name    = "resctrl",
	.mount   = rdt_mount,
	.kill_sb = rdt_kill_sb,
};

static struct kernfs_syscall_ops rdtgroup_kf_syscall_ops = {
};

static int __init rdtgroup_setup_root(void)
{
	int ret;

	rdt_root = kernfs_create_root(&rdtgroup_kf_syscall_ops,
				      KERNFS_ROOT_CREATE_DEACTIVATED,
				      &rdtgroup_default);
	if (IS_ERR(rdt_root))
		return PTR_ERR(rdt_root);

	mutex_lock(&rdtgroup_mutex);

	rdtgroup_default.closid = 0;
	list_add(&rdtgroup_default.rdtgroup_list, &rdt_all_groups);

	rdtgroup_default.kn = rdt_root->kn;
	kernfs_activate(rdtgroup_default.kn);

	mutex_unlock(&rdtgroup_mutex);

	return ret;
}

/*
 * rdtgroup_init - rdtgroup initialization
 *
 * Setup resctrl file system including set up root, create mount point,
 * register rdtgroup filesystem, and initialize files under root directory.
 *
 * Return: 0 on success or -errno
 */
int __init rdtgroup_init(void)
{
	int ret = 0;

	ret = rdtgroup_setup_root();
	if (ret)
		return ret;

	ret = sysfs_create_mount_point(fs_kobj, "resctrl");
	if (ret)
		goto cleanup_root;

	ret = register_filesystem(&rdt_fs_type);
	if (ret)
		goto cleanup_mountpoint;

	return 0;

cleanup_mountpoint:
	sysfs_remove_mount_point(fs_kobj, "resctrl");
cleanup_root:
	kernfs_destroy_root(rdt_root);

	return ret;
}
