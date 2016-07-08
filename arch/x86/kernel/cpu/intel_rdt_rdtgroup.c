/*
 * Resource Director Technology(RDT)
 * - User interface for Resource Alloction in RDT.
 *
 * Copyright (C) 2016 Intel Corporation
 *
 * 2016 Written by
 *    Fenghua Yu <fenghua.yu@intel.com>
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
#include <linux/cred.h>
#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/init_task.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/magic.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/pid_namespace.h>
#include <linux/vmalloc.h>
#include <linux/atomic.h>
#include <linux/cpumask.h>
#include <linux/cacheinfo.h>
#include <asm/intel_rdt_rdtgroup.h>
#include <asm/intel_rdt.h>

#define RDTGROUP_FILE_NAME_LEN	(MAX_RDTGROUP_TYPE_NAMELEN +	\
				 MAX_RFTYPE_NAME + 2)

static int rdt_info_show(struct seq_file *seq, void *v);
static int rdt_max_closid_show(struct seq_file *seq, void *v);
static int rdt_max_cbm_len_show(struct seq_file *seq, void *v);
static int domain_to_cache_id_show(struct seq_file *seq, void *v);
static int rdtgroup_mkdir(struct kernfs_node *parent_kn, const char *name,
			umode_t mode);
static int rdtgroup_rmdir(struct kernfs_node *kn);
static struct dentry *rdt_mount(struct file_system_type *fs_type,
			 int flags, const char *unused_dev_name,
			 void *data);
static void rdt_kill_sb(struct super_block *sb);

/* rdtgroup core interface files */
static struct rftype rdtgroup_root_base_files[] = {
	{
		.name = "tasks",
		.seq_show = rdtgroup_tasks_show,
		.write = rdtgroup_tasks_write,
	},
	{
		.name = "cpus",
		.write = rdtgroup_cpus_write,
		.seq_show = rdtgroup_cpus_show,
	},
	{
		.name = "schemata",
		.write = rdtgroup_schemata_write,
		.seq_show = rdtgroup_schemata_show,
	},
};

static struct rftype info_files[] = {
	{
		.name = "info",
		.seq_show = rdt_info_show,
	},
};

/* rdtgroup information files for one cache resource. */
static struct rftype res_info_files[] = {
	{
		.name = "max_closid",
		.seq_show = rdt_max_closid_show,
	},
	{
		.name = "max_cbm_len",
		.seq_show = rdt_max_cbm_len_show,
	},
	{
		.name = "domain_to_cache_id",
		.seq_show = domain_to_cache_id_show,
	},
};

static struct rftype rdtgroup_partition_base_files[] = {
	{
		.name = "tasks",
		.seq_show = rdtgroup_tasks_show,
		.write = rdtgroup_tasks_write,
	},
	{
		.name = "cpus",
		.write = rdtgroup_cpus_write,
		.seq_show = rdtgroup_cpus_show,
	},
	{
		.name = "schemata",
		.write = rdtgroup_schemata_write,
		.seq_show = rdtgroup_schemata_show,
	},
};

static struct kernfs_syscall_ops rdtgroup_kf_syscall_ops = {
	.mkdir          = rdtgroup_mkdir,
	.rmdir          = rdtgroup_rmdir,
};

static struct file_system_type rdt_fs_type = {
	.name = "resctrl",
	.mount = rdt_mount,
	.kill_sb = rdt_kill_sb,
};

struct rdtgroup *root_rdtgrp;
static struct rftype rdtgroup_partition_base_files[];
struct cache_domain cache_domains[MAX_CACHE_LEAVES];
/* The default hierarchy. */
struct rdtgroup_root rdtgrp_dfl_root;
static struct list_head rdtgroups;
bool rdtgroup_mounted;

/*
 * kernfs_root - find out the kernfs_root a kernfs_node belongs to
 * @kn: kernfs_node of interest
 *
 * Return the kernfs_root @kn belongs to.
 */
static inline struct kernfs_root *get_kernfs_root(struct kernfs_node *kn)
{
	if (kn->parent)
		kn = kn->parent;
	return kn->dir.root;
}

/*
 * rdtgroup_file_mode - deduce file mode of a control file
 * @cft: the control file in question
 *
 * S_IRUGO for read, S_IWUSR for write.
 */
static umode_t rdtgroup_file_mode(const struct rftype *rft)
{
	umode_t mode = 0;

	if (rft->read_u64 || rft->read_s64 || rft->seq_show)
		mode |= S_IRUGO;

	if (rft->write_u64 || rft->write_s64 || rft->write)
		mode |= S_IWUSR;

	return mode;
}

/* set uid and gid of rdtgroup dirs and files to that of the creator */
static int rdtgroup_kn_set_ugid(struct kernfs_node *kn)
{
	struct iattr iattr = { .ia_valid = ATTR_UID | ATTR_GID,
			       .ia_uid = current_fsuid(),
			       .ia_gid = current_fsgid(), };

	if (uid_eq(iattr.ia_uid, GLOBAL_ROOT_UID) &&
	    gid_eq(iattr.ia_gid, GLOBAL_ROOT_GID))
		return 0;

	return kernfs_setattr(kn, &iattr);
}

static int rdtgroup_add_file(struct kernfs_node *parent_kn, struct rftype *rft)
{
	char name[RDTGROUP_FILE_NAME_LEN];
	struct kernfs_node *kn;
	struct lock_class_key *key = NULL;
	int ret;

	strncpy(name, rft->name, RDTGROUP_FILE_NAME_LEN);
	kn = __kernfs_create_file(parent_kn, name, rdtgroup_file_mode(rft),
				  0, rft->kf_ops, rft, NULL, key);
	if (IS_ERR(kn))
		return PTR_ERR(kn);

	ret = rdtgroup_kn_set_ugid(kn);
	if (ret) {
		kernfs_remove(kn);
		return ret;
	}

	return 0;
}

static void rdtgroup_rm_file(struct kernfs_node *kn, const struct rftype *rft)
{
	char name[RDTGROUP_FILE_NAME_LEN];

	strncpy(name, rft->name, RDTGROUP_FILE_NAME_LEN);
	kernfs_remove_by_name(kn, name);
}

static void rdtgroup_rm_files(struct kernfs_node *kn, struct rftype *rft,
			      const struct rftype *end)
{
	for (; rft != end; rft++)
		rdtgroup_rm_file(kn, rft);
}

static int rdtgroup_add_files(struct kernfs_node *kn, struct rftype *rfts,
			      const struct rftype *end)
{
	struct rftype *rft;
	int ret;

	lockdep_assert_held(&rdtgroup_mutex);

	for (rft = rfts; rft != end; rft++) {
		ret = rdtgroup_add_file(kn, rft);
		if (ret) {
			pr_warn("%s: failed to add %s, err=%d\n",
				__func__, rft->name, ret);
			rdtgroup_rm_files(kn, rft, end);
			return ret;
		}
	}

	return 0;
}

/*
 * Get resource type from name in kernfs_node. This can be extended to
 * multi-resources (e.g. L2). Right now simply return RESOURCE_L3 because
 * we only have L3 support.
 */
static enum resource_type get_kn_res_type(struct kernfs_node *kn)
{
	return RESOURCE_L3;
}

static int rdt_max_closid_show(struct seq_file *seq, void *v)
{
	struct kernfs_open_file *of = seq->private;

	switch (get_kn_res_type(of->kn)) {
	case RESOURCE_L3:
		seq_printf(seq, "%d\n",
			boot_cpu_data.x86_l3_max_closid);
		break;
	default:
		break;
	}

	return 0;
}

static int rdt_max_cbm_len_show(struct seq_file *seq, void *v)
{
	struct kernfs_open_file *of = seq->private;

	switch (get_kn_res_type(of->kn)) {
	case RESOURCE_L3:
		seq_printf(seq, "%d\n",
			boot_cpu_data.x86_l3_max_cbm_len);
		break;
	default:
		break;
	}

	return 0;
}

static int get_shared_domain(int domain, int level)
{
	int sd;

	for_each_cache_domain(sd, 0, shared_domain_num) {
		if (cat_l3_enabled && level == CACHE_LEVEL3) {
			if (shared_domain[sd].l3_domain == domain)
				return sd;
		}
	}

	return -1;
}

static void rdt_info_show_cat(struct seq_file *seq, int level)
{
	int domain;
	int domain_num = get_domain_num(level);
	int closid;
	u64 cbm;
	struct clos_cbm_table **cctable;
	int maxid;
	int shared_domain;
	int cnt;

	if (level == CACHE_LEVEL3)
		cctable = l3_cctable;
	else
		return;

	maxid = cconfig.max_closid;
	for (domain = 0; domain < domain_num; domain++) {
		seq_printf(seq, "domain %d:\n", domain);
		shared_domain = get_shared_domain(domain, level);
		for (closid = 0; closid < maxid; closid++) {
			int dindex, iindex;

			if (test_bit(closid,
			(unsigned long *)cconfig.closmap[shared_domain])) {
				dindex = get_dcbm_table_index(closid);
				cbm = cctable[domain][dindex].cbm;
				cnt = cctable[domain][dindex].clos_refcnt;
				seq_printf(seq, "cbm[%d]=%lx, refcnt=%d\n",
					 dindex, (unsigned long)cbm, cnt);
				if (cdp_enabled) {
					iindex = get_icbm_table_index(closid);
					cbm = cctable[domain][iindex].cbm;
					cnt =
					   cctable[domain][iindex].clos_refcnt;
					seq_printf(seq,
						   "cbm[%d]=%lx, refcnt=%d\n",
						   iindex, (unsigned long)cbm,
						   cnt);
				}
			} else {
				cbm = max_cbm(level);
				cnt = 0;
				dindex = get_dcbm_table_index(closid);
				seq_printf(seq, "cbm[%d]=%lx, refcnt=%d\n",
					 dindex, (unsigned long)cbm, cnt);
				if (cdp_enabled) {
					iindex = get_icbm_table_index(closid);
					seq_printf(seq,
						 "cbm[%d]=%lx, refcnt=%d\n",
						 iindex, (unsigned long)cbm,
						 cnt);
				}
			}
		}
	}
}

static void show_shared_domain(struct seq_file *seq)
{
	int domain;

	seq_puts(seq, "Shared domains:\n");

	for_each_cache_domain(domain, 0, shared_domain_num) {
		struct shared_domain *sd;

		sd = &shared_domain[domain];
		seq_printf(seq, "domain[%d]:", domain);
		if (cat_enabled(CACHE_LEVEL3))
			seq_printf(seq, "l3_domain=%d ", sd->l3_domain);
		seq_printf(seq, "cpumask=%*pb\n",
			   cpumask_pr_args(&sd->cpumask));
	}
}

static int rdt_info_show(struct seq_file *seq, void *v)
{
	show_shared_domain(seq);

	if (cat_l3_enabled) {
		if (rdt_opts.verbose)
			rdt_info_show_cat(seq, CACHE_LEVEL3);
	}

	seq_puts(seq, "\n");

	return 0;
}

static int res_type_to_level(enum resource_type res_type, int *level)
{
	int ret = 0;

	switch (res_type) {
	case RESOURCE_L3:
		*level = CACHE_LEVEL3;
		break;
	case RESOURCE_NUM:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int domain_to_cache_id_show(struct seq_file *seq, void *v)
{
	struct kernfs_open_file *of = seq->private;
	enum resource_type res_type;
	int domain;
	int leaf;
	int level = 0;
	int ret;

	res_type = (enum resource_type)of->kn->parent->priv;

	ret = res_type_to_level(res_type, &level);
	if (ret)
		return 0;

	leaf =	get_cache_leaf(level, 0);

	for (domain = 0; domain < get_domain_num(level); domain++) {
		unsigned int cid;

		cid = cache_domains[leaf].shared_cache_id[domain];
		seq_printf(seq, "%d:%d\n", domain, cid);
	}

	return 0;
}

static int rdtgroup_procs_write_permission(struct task_struct *task,
					   struct kernfs_open_file *of)
{
	const struct cred *cred = current_cred();
	const struct cred *tcred = get_task_cred(task);
	int ret = 0;

	/*
	 * even if we're attaching all tasks in the thread group, we only
	 * need to check permissions on one of them.
	 */
	if (!uid_eq(cred->euid, GLOBAL_ROOT_UID) &&
	    !uid_eq(cred->euid, tcred->uid) &&
	    !uid_eq(cred->euid, tcred->suid))
		ret = -EPERM;

	put_cred(tcred);
	return ret;
}

static int info_populate_dir(struct kernfs_node *kn)
{
	struct rftype *rfts;

	rfts = info_files;
	return rdtgroup_add_files(kn, rfts, rfts + ARRAY_SIZE(info_files));
}

static int res_info_populate_dir(struct kernfs_node *kn)
{
	struct rftype *rfts;

	rfts = res_info_files;
	return rdtgroup_add_files(kn, rfts, rfts + ARRAY_SIZE(res_info_files));
}

static int rdtgroup_populate_dir(struct kernfs_node *kn)
{
	struct rftype *rfts;

	rfts = rdtgroup_root_base_files;
	return rdtgroup_add_files(kn, rfts,
				  rfts + ARRAY_SIZE(rdtgroup_root_base_files));
}

static int rdtgroup_partition_populate_dir(struct kernfs_node *kn)
{
	struct rftype *rfts;

	rfts = rdtgroup_partition_base_files;
	return rdtgroup_add_files(kn, rfts,
			rfts + ARRAY_SIZE(rdtgroup_partition_base_files));
}

LIST_HEAD(rdtgroup_lists);
static void init_rdtgroup_root(struct rdtgroup_root *root)
{
	struct rdtgroup *rdtgrp = &root->rdtgrp;

	INIT_LIST_HEAD(&rdtgrp->rdtgroup_list);
	list_add_tail(&rdtgrp->rdtgroup_list, &rdtgroup_lists);
	atomic_set(&root->nr_rdtgrps, 1);
	rdtgrp->root = root;
}

static struct kernfs_syscall_ops rdtgroup_kf_syscall_ops;
struct rdtgroup *rdtgroup_kn_lock_live(struct kernfs_node *kn)
{
	struct rdtgroup *rdtgrp;

	mutex_lock(&rdtgroup_mutex);

	if (kernfs_type(kn) == KERNFS_DIR)
		rdtgrp = kn->priv;
	else
		rdtgrp = kn->parent->priv;

	kernfs_break_active_protection(kn);

	return rdtgrp;
}

void rdtgroup_kn_unlock(struct kernfs_node *kn)
{
	mutex_unlock(&rdtgroup_mutex);

	kernfs_unbreak_active_protection(kn);
}

static char *res_info_dir_name(enum resource_type res_type, char *name)
{
	switch (res_type) {
	case RESOURCE_L3:
		strncpy(name, "l3", RDTGROUP_FILE_NAME_LEN);
		break;
	default:
		break;
	}

	return name;
}

static int create_res_info(enum resource_type res_type,
			   struct kernfs_node *parent_kn)
{
	struct kernfs_node *kn;
	char name[RDTGROUP_FILE_NAME_LEN];
	int ret;

	res_info_dir_name(res_type, name);
	kn = kernfs_create_dir(parent_kn, name, parent_kn->mode, NULL);
	if (IS_ERR(kn)) {
		ret = PTR_ERR(kn);
		goto out;
	}

	/*
	 * This extra ref will be put in kernfs_remove() and guarantees
	 * that @rdtgrp->kn is always accessible.
	 */
	kernfs_get(kn);

	ret = rdtgroup_kn_set_ugid(kn);
	if (ret)
		goto out_destroy;

	ret = res_info_populate_dir(kn);
	if (ret)
		goto out_destroy;

	kernfs_activate(kn);

	ret = 0;
	goto out;

out_destroy:
	kernfs_remove(kn);
out:
	return ret;

}

static int rdtgroup_create_info_dir(struct kernfs_node *parent_kn,
				    const char *name)
{
	struct kernfs_node *kn;
	int ret;

	if (parent_kn != root_rdtgrp->kn)
		return -EPERM;

	/* create the directory */
	kn = kernfs_create_dir(parent_kn, "info", parent_kn->mode, root_rdtgrp);
	if (IS_ERR(kn)) {
		ret = PTR_ERR(kn);
		goto out;
	}

	ret = info_populate_dir(kn);
	if (ret)
		goto out_destroy;

	if (cat_enabled(CACHE_LEVEL3))
		create_res_info(RESOURCE_L3, kn);

	/*
	 * This extra ref will be put in kernfs_remove() and guarantees
	 * that @rdtgrp->kn is always accessible.
	 */
	kernfs_get(kn);

	ret = rdtgroup_kn_set_ugid(kn);
	if (ret)
		goto out_destroy;

	kernfs_activate(kn);

	ret = 0;
	goto out;

out_destroy:
	kernfs_remove(kn);
out:
	return ret;
}

static int rdtgroup_setup_root(struct rdtgroup_root *root,
			       unsigned long ss_mask)
{
	int ret;

	root_rdtgrp = &root->rdtgrp;

	lockdep_assert_held(&rdtgroup_mutex);

	root->kf_root = kernfs_create_root(&rdtgroup_kf_syscall_ops,
					   KERNFS_ROOT_CREATE_DEACTIVATED,
					   root_rdtgrp);
	if (IS_ERR(root->kf_root)) {
		ret = PTR_ERR(root->kf_root);
		goto out;
	}
	root_rdtgrp->kn = root->kf_root->kn;

	ret = rdtgroup_populate_dir(root->kf_root->kn);
	if (ret)
		goto destroy_root;

	rdtgroup_create_info_dir(root->kf_root->kn, "info_dir");

	/*
	 * Link the root rdtgroup in this hierarchy into all the css_set
	 * objects.
	 */
	WARN_ON(atomic_read(&root->nr_rdtgrps) != 1);

	kernfs_activate(root_rdtgrp->kn);
	ret = 0;
	goto out;

destroy_root:
	kernfs_destroy_root(root->kf_root);
	root->kf_root = NULL;
out:
	return ret;
}

static int get_shared_cache_id(int cpu, int level)
{
	struct cpuinfo_x86 *c;
	int index_msb;
	struct cpu_cacheinfo *this_cpu_ci;
	struct cacheinfo *this_leaf;

	this_cpu_ci = get_cpu_cacheinfo(cpu);

	this_leaf = this_cpu_ci->info_list + level_to_leaf(level);
	return this_leaf->id;
	return c->apicid >> index_msb;
}

static void init_cache_domain(int cpu, int leaf)
{
	struct cpu_cacheinfo *this_cpu_ci;
	struct cpumask *mask;
	unsigned int level;
	struct cacheinfo *this_leaf;
	int domain;

	this_cpu_ci = get_cpu_cacheinfo(cpu);
	this_leaf = this_cpu_ci->info_list + leaf;
	cache_domains[leaf].level = this_leaf->level;
	mask = &this_leaf->shared_cpu_map;
	for (domain = 0; domain < MAX_CACHE_DOMAINS; domain++) {
		if (cpumask_test_cpu(cpu,
			&cache_domains[leaf].shared_cpu_map[domain]))
			return;
	}
	if (domain == MAX_CACHE_DOMAINS) {
		domain = cache_domains[leaf].max_cache_domains_num++;

		cache_domains[leaf].shared_cpu_map[domain] = *mask;

		level = cache_domains[leaf].level;
		cache_domains[leaf].shared_cache_id[domain] =
			get_shared_cache_id(cpu, level);
	}
}

static __init void init_cache_domains(void)
{
	int cpu;
	int leaf;

	for (leaf = 0; leaf < get_cpu_cacheinfo(0)->num_leaves; leaf++) {
		for_each_online_cpu(cpu)
			init_cache_domain(cpu, leaf);
	}
}

void rdtgroup_exit(struct task_struct *tsk)
{

	if (!list_empty(&tsk->rg_list)) {
		struct rdtgroup *rdtgrp = tsk->rdtgroup;

		list_del_init(&tsk->rg_list);
		tsk->rdtgroup = NULL;
		atomic_dec(&rdtgrp->refcount);
	}
}

static void rdtgroup_destroy_locked(struct rdtgroup *rdtgrp)
	__releases(&rdtgroup_mutex) __acquires(&rdtgroup_mutex)
{
	int shared_domain;
	int closid;

	lockdep_assert_held(&rdtgroup_mutex);

	/* free closid occupied by this rdtgroup. */
	for_each_cache_domain(shared_domain, 0, shared_domain_num) {
		closid = rdtgrp->resource.closid[shared_domain];
		closid_put(closid, shared_domain);
	}

	list_del_init(&rdtgrp->rdtgroup_list);

	/*
	 * Remove @rdtgrp directory along with the base files.  @rdtgrp has an
	 * extra ref on its kn.
	 */
	kernfs_remove(rdtgrp->kn);
}

static int rdtgroup_mkdir(struct kernfs_node *parent_kn, const char *name,
			umode_t mode)
{
	struct rdtgroup *parent, *rdtgrp;
	struct rdtgroup_root *root;
	struct kernfs_node *kn;
	int ret;

	if (parent_kn != root_rdtgrp->kn)
		return -EPERM;

	/* Do not accept '\n' to avoid unparsable situation.
	 */
	if (strchr(name, '\n'))
		return -EINVAL;

	parent = rdtgroup_kn_lock_live(parent_kn);
	if (!parent)
		return -ENODEV;
	root = parent->root;

	/* allocate the rdtgroup. */
	rdtgrp = kzalloc(sizeof(*rdtgrp), GFP_KERNEL);
	if (!rdtgrp) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	INIT_LIST_HEAD(&rdtgrp->pset.tasks);

	cpumask_clear(&rdtgrp->cpu_mask);

	rdtgrp->root = root;

	/* create the directory */
	kn = kernfs_create_dir(parent->kn, name, mode, rdtgrp);
	if (IS_ERR(kn)) {
		ret = PTR_ERR(kn);
		goto out_cancel_ref;
	}
	rdtgrp->kn = kn;

	/*
	 * This extra ref will be put in kernfs_remove() and guarantees
	 * that @rdtgrp->kn is always accessible.
	 */
	kernfs_get(kn);

	atomic_inc(&root->nr_rdtgrps);

	ret = rdtgroup_kn_set_ugid(kn);
	if (ret)
		goto out_destroy;

	ret = rdtgroup_partition_populate_dir(kn);
	if (ret)
		goto out_destroy;

	kernfs_activate(kn);

	list_add_tail(&rdtgrp->rdtgroup_list, &rdtgroup_lists);
	/* Generate default schema for rdtgrp. */
	ret = get_default_resources(rdtgrp);
	if (ret)
		goto out_destroy;

	ret = 0;
	goto out_unlock;

out_cancel_ref:
	kfree(rdtgrp);
out_unlock:
	rdtgroup_kn_unlock(parent_kn);
	return ret;

out_destroy:
	rdtgroup_destroy_locked(rdtgrp);
	goto out_unlock;
}

static int rdtgroup_rmdir(struct kernfs_node *kn)
{
	struct rdtgroup *rdtgrp;
	int cpu;
	int ret = 0;

	rdtgrp = rdtgroup_kn_lock_live(kn);
	if (!rdtgrp)
		return -ENODEV;

	if (!list_empty(&rdtgrp->pset.tasks)) {
		ret = -EBUSY;
		goto out;
	}

	for_each_cpu(cpu, &rdtgrp->cpu_mask)
		per_cpu(cpu_rdtgroup, cpu) = root_rdtgrp;

	rdtgroup_destroy_locked(rdtgrp);

out:
	rdtgroup_kn_unlock(kn);
	return ret;
}
static int
rdtgroup_move_task_all(struct rdtgroup *src_rdtgrp, struct rdtgroup *dst_rdtgrp)
{
	struct list_head *tasks;

	tasks = &src_rdtgrp->pset.tasks;
	while (!list_empty(tasks)) {
		struct task_struct *tsk;
		struct list_head *pos;
		pid_t pid;
		int ret;

		pos = tasks->next;
		tsk = list_entry(pos, struct task_struct, rg_list);
		pid = tsk->pid;
		ret = rdtgroup_move_task(pid, dst_rdtgrp, false, NULL);
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * Forcibly remove all of subdirectories under root.
 */
static void rmdir_all_sub(void)
{
	struct rdtgroup *rdtgrp;
	int cpu;
	struct list_head *l;
	struct task_struct *p;

	/* Move all tasks from sub rdtgroups to default */
	rcu_read_lock();
	for_each_process(p) {
		if (p->rdtgroup)
			p->rdtgroup = NULL;
	}
	rcu_read_unlock();

	while (!list_is_last(&root_rdtgrp->rdtgroup_list, &rdtgroup_lists)) {
		l = rdtgroup_lists.next;
		if (l == &root_rdtgrp->rdtgroup_list)
			l = l->next;

		rdtgrp = list_entry(l, struct rdtgroup, rdtgroup_list);
		if (rdtgrp == root_rdtgrp)
			continue;

		for_each_cpu(cpu, &rdtgrp->cpu_mask)
			per_cpu(cpu_rdtgroup, cpu) = root_rdtgrp;

		rdtgroup_destroy_locked(rdtgrp);
	}
}

static int parse_rdtgroupfs_options(char *data)
{
	char *token, *o = data;
	int nr_opts = 0;

	while ((token = strsep(&o, ",")) != NULL) {
		nr_opts++;

		if (!*token)
			return -EINVAL;
		if (!strcmp(token, "cdp")) {
			/* Enable CDP */
			rdt_opts.cdp_enabled = true;
			continue;
		}
		if (!strcmp(token, "verbose")) {
			rdt_opts.verbose = true;
			continue;
		}
	}

	return 0;
}

static void release_root_closid(void)
{
	int domain;
	int closid;

	if (!root_rdtgrp->resource.valid)
		return;

	for_each_cache_domain(domain, 0, shared_domain_num) {
		/* Put closid in root rdtgrp's domain if valid. */
		closid = root_rdtgrp->resource.closid[domain];
		closid_put(closid, domain);
	}
}

static ssize_t rdtgroup_file_write(struct kernfs_open_file *of, char *buf,
				 size_t nbytes, loff_t off)
{
	struct rftype *rft = of->kn->priv;

	if (rft->write)
		return rft->write(of, buf, nbytes, off);

	return -EINVAL;
}

static void *rdtgroup_seqfile_start(struct seq_file *seq, loff_t *ppos)
{
	return seq_rft(seq)->seq_start(seq, ppos);
}

static void *rdtgroup_seqfile_next(struct seq_file *seq, void *v, loff_t *ppos)
{
	return seq_rft(seq)->seq_next(seq, v, ppos);
}

static void rdtgroup_seqfile_stop(struct seq_file *seq, void *v)
{
	seq_rft(seq)->seq_stop(seq, v);
}

static int rdtgroup_seqfile_show(struct seq_file *m, void *arg)
{
	struct rftype *rft = seq_rft(m);

	if (rft->seq_show)
		return rft->seq_show(m, arg);
	return 0;
}

static struct kernfs_ops rdtgroup_kf_ops = {
	.atomic_write_len	= PAGE_SIZE,
	.write			= rdtgroup_file_write,
	.seq_start		= rdtgroup_seqfile_start,
	.seq_next		= rdtgroup_seqfile_next,
	.seq_stop		= rdtgroup_seqfile_stop,
	.seq_show		= rdtgroup_seqfile_show,
};

static struct kernfs_ops rdtgroup_kf_single_ops = {
	.atomic_write_len	= PAGE_SIZE,
	.write			= rdtgroup_file_write,
	.seq_show		= rdtgroup_seqfile_show,
};

static void rdtgroup_exit_rftypes(struct rftype *rfts)
{
	struct rftype *rft;

	for (rft = rfts; rft->name[0] != '\0'; rft++) {
		/* free copy for custom atomic_write_len, see init_cftypes() */
		if (rft->max_write_len && rft->max_write_len != PAGE_SIZE)
			kfree(rft->kf_ops);
		rft->kf_ops = NULL;

		/* revert flags set by rdtgroup core while adding @cfts */
		rft->flags &= ~(__RFTYPE_ONLY_ON_DFL | __RFTYPE_NOT_ON_DFL);
	}
}

static int rdtgroup_init_rftypes(struct rftype *rfts)
{
	struct rftype *rft;

	for (rft = rfts; rft->name[0] != '\0'; rft++) {
		struct kernfs_ops *kf_ops;

		if (rft->seq_start)
			kf_ops = &rdtgroup_kf_ops;
		else
			kf_ops = &rdtgroup_kf_single_ops;

		/*
		 * Ugh... if @cft wants a custom max_write_len, we need to
		 * make a copy of kf_ops to set its atomic_write_len.
		 */
		if (rft->max_write_len && rft->max_write_len != PAGE_SIZE) {
			kf_ops = kmemdup(kf_ops, sizeof(*kf_ops), GFP_KERNEL);
			if (!kf_ops) {
				rdtgroup_exit_rftypes(rfts);
				return -ENOMEM;
			}
			kf_ops->atomic_write_len = rft->max_write_len;
		}

		rft->kf_ops = kf_ops;
	}

	return 0;
}

/*
 * rdtgroup_init - rdtgroup initialization
 *
 * Register rdtgroup filesystem, and initialize any subsystems that didn't
 * request early init.
 */
int __init rdtgroup_init(void)
{
	int cpu;

	WARN_ON(rdtgroup_init_rftypes(rdtgroup_root_base_files));

	WARN_ON(rdtgroup_init_rftypes(res_info_files));
	WARN_ON(rdtgroup_init_rftypes(info_files));

	WARN_ON(rdtgroup_init_rftypes(rdtgroup_partition_base_files));
	mutex_lock(&rdtgroup_mutex);

	init_rdtgroup_root(&rdtgrp_dfl_root);
	WARN_ON(rdtgroup_setup_root(&rdtgrp_dfl_root, 0));

	mutex_unlock(&rdtgroup_mutex);

	WARN_ON(sysfs_create_mount_point(fs_kobj, "resctrl"));
	WARN_ON(register_filesystem(&rdt_fs_type));
	init_cache_domains();

	INIT_LIST_HEAD(&rdtgroups);

	for_each_online_cpu(cpu)
		per_cpu(cpu_rdtgroup, cpu) = root_rdtgrp;

	return 0;
}

void rdtgroup_fork(struct task_struct *child)
{
	struct rdtgroup *rdtgrp;

	INIT_LIST_HEAD(&child->rg_list);
	if (!rdtgroup_mounted)
		return;

	mutex_lock(&rdtgroup_mutex);

	rdtgrp = current->rdtgroup;
	if (!rdtgrp)
		goto out;

	list_add_tail(&child->rg_list, &rdtgrp->pset.tasks);
	child->rdtgroup = rdtgrp;
	atomic_inc(&rdtgrp->refcount);

out:
	mutex_unlock(&rdtgroup_mutex);
}

static struct dentry *rdt_mount(struct file_system_type *fs_type,
			 int flags, const char *unused_dev_name,
			 void *data)
{
	struct super_block *pinned_sb = NULL;
	struct rdtgroup_root *root;
	struct dentry *dentry;
	int ret;
	bool new_sb;

	/*
	 * The first time anyone tries to mount a rdtgroup, enable the list
	 * linking tasks and fix up all existing tasks.
	 */
	if (rdtgroup_mounted)
		return ERR_PTR(-EBUSY);

	rdt_opts.cdp_enabled = false;
	rdt_opts.verbose = false;
	cdp_enabled = false;

	ret = parse_rdtgroupfs_options(data);
	if (ret)
		goto out_mount;

	if (rdt_opts.cdp_enabled) {
		cdp_enabled = true;
		cconfig.max_closid >>= cdp_enabled;
		pr_info("CDP is enabled\n");
	}

	init_msrs(cdp_enabled);

	root = &rdtgrp_dfl_root;

	ret = get_default_resources(&root->rdtgrp);
	if (ret)
		return ERR_PTR(-ENOSPC);

out_mount:
	dentry = kernfs_mount(fs_type, flags, root->kf_root,
			      RDTGROUP_SUPER_MAGIC,
			      &new_sb);
	if (IS_ERR(dentry) || !new_sb)
		goto out_unlock;

	/*
	 * If @pinned_sb, we're reusing an existing root and holding an
	 * extra ref on its sb.  Mount is complete.  Put the extra ref.
	 */
	if (pinned_sb) {
		WARN_ON(new_sb);
		deactivate_super(pinned_sb);
	}

	INIT_LIST_HEAD(&root->rdtgrp.pset.tasks);

	cpumask_copy(&root->rdtgrp.cpu_mask, cpu_online_mask);
	static_key_slow_inc(&rdt_enable_key);
	rdtgroup_mounted = true;

	return dentry;

out_unlock:
	return ERR_PTR(ret);
}

static void rdt_kill_sb(struct super_block *sb)
{
	mutex_lock(&rdtgroup_mutex);

	rmdir_all_sub();

	static_key_slow_dec(&rdt_enable_key);

	release_root_closid();
	root_rdtgrp->resource.valid = false;

	/* Restore max_closid to original value. */
	cconfig.max_closid <<= cdp_enabled;

	kernfs_kill_sb(sb);
	INIT_LIST_HEAD(&root_rdtgrp->pset.tasks);
	rdtgroup_mounted = false;

	mutex_unlock(&rdtgroup_mutex);
}
