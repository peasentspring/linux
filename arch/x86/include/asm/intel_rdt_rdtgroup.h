#ifndef _RDT_PGROUP_H
#define _RDT_PGROUP_H
#define MAX_RDTGROUP_TYPE_NAMELEN	32
#define MAX_RDTGROUP_ROOT_NAMELEN	64
#define MAX_RFTYPE_NAME			64

#include <linux/kernfs.h>
#include <asm/intel_rdt.h>

/* Defined in intel_rdt_rdtgroup.c.*/
extern int __init rdtgroup_init(void);
extern void rdtgroup_exit(struct task_struct *tsk);
extern bool rdtgroup_mounted;

/* Defined in intel_rdt.c. */
extern struct list_head rdtgroup_lists;
extern struct rdtgroup *rdtgroup_kn_lock_live(struct kernfs_node *kn);
extern void rdtgroup_kn_unlock(struct kernfs_node *kn);

/* Defiend in intel_rdt_schemata.c. */
extern int get_default_resources(struct rdtgroup *rdtgrp);
extern ssize_t rdtgroup_schemata_write(struct kernfs_open_file *of,
				char *buf, size_t nbytes, loff_t off);
extern int rdtgroup_schemata_show(struct seq_file *s, void *v);

/* cftype->flags */
enum {
	RFTYPE_WORLD_WRITABLE = (1 << 4),/* (DON'T USE FOR NEW FILES) S_IWUGO */

	/* internal flags, do not use outside rdtgroup core proper */
	__RFTYPE_ONLY_ON_DFL  = (1 << 16),/* only on default hierarchy */
	__RFTYPE_NOT_ON_DFL   = (1 << 17),/* not on default hierarchy */
};

#define CACHE_LEVEL3		3

struct cache_resource {
	u64 *cbm;
	u64 *cbm2;
	int *closid;
	int *refcnt;
};

struct rdt_resource {
	bool valid;
	int closid[MAX_CACHE_DOMAINS];
	/* Add more resources here. */
};

struct rdtgroup {
	struct kernfs_node *kn;		/* rdtgroup kernfs entry */

	struct rdtgroup_root *root;

	struct list_head rdtgroup_list;

	atomic_t refcount;
	struct cpumask cpu_mask;
	char schema[1024];

	struct rdt_resource resource;

	/* ids of the ancestors at each level including self */
	int ancestor_ids[];
};

struct rftype {
	/*
	 * By convention, the name should begin with the name of the
	 * subsystem, followed by a period.  Zero length string indicates
	 * end of cftype array.
	 */
	char name[MAX_CFTYPE_NAME];
	unsigned long private;

	/*
	 * The maximum length of string, excluding trailing nul, that can
	 * be passed to write.  If < PAGE_SIZE-1, PAGE_SIZE-1 is assumed.
	 */
	size_t max_write_len;

	/* CFTYPE_* flags */
	unsigned int flags;

	/*
	 * Fields used for internal bookkeeping.  Initialized automatically
	 * during registration.
	 */
	struct kernfs_ops *kf_ops;

	/*
	 * read_u64() is a shortcut for the common case of returning a
	 * single integer. Use it in place of read()
	 */
	u64 (*read_u64)(struct rftype *rft);
	/*
	 * read_s64() is a signed version of read_u64()
	 */
	s64 (*read_s64)(struct rftype *rft);

	/* generic seq_file read interface */
	int (*seq_show)(struct seq_file *sf, void *v);

	/* optional ops, implement all or none */
	void *(*seq_start)(struct seq_file *sf, loff_t *ppos);
	void *(*seq_next)(struct seq_file *sf, void *v, loff_t *ppos);
	void (*seq_stop)(struct seq_file *sf, void *v);

	/*
	 * write_u64() is a shortcut for the common case of accepting
	 * a single integer (as parsed by simple_strtoull) from
	 * userspace. Use in place of write(); return 0 or error.
	 */
	int (*write_u64)(struct rftype *rft, u64 val);
	/*
	 * write_s64() is a signed version of write_u64()
	 */
	int (*write_s64)(struct rftype *rft, s64 val);

	/*
	 * write() is the generic write callback which maps directly to
	 * kernfs write operation and overrides all other operations.
	 * Maximum write size is determined by ->max_write_len.  Use
	 * of_css/cft() to access the associated css and cft.
	 */
	ssize_t (*write)(struct kernfs_open_file *of,
			 char *buf, size_t nbytes, loff_t off);
};

struct rdtgroup_root {
	struct kernfs_root *kf_root;

	/* Unique id for this hierarchy. */
	int hierarchy_id;

	/* The root rdtgroup.  Root is destroyed on its release. */
	struct rdtgroup rdtgrp;

	/* Number of rdtgroups in the hierarchy */
	atomic_t nr_rdtgrps;

	/* Hierarchy-specific flags */
	unsigned int flags;

	/* IDs for rdtgroups in this hierarchy */
	struct idr rdtgroup_idr;

	/* The name for this hierarchy - may be empty */
	char name[MAX_RDTGROUP_ROOT_NAMELEN];
};

/* get rftype from of */
static inline struct rftype *of_rft(struct kernfs_open_file *of)
{
	return of->kn->priv;
}

/* get rftype from seq_file */
static inline struct rftype *seq_rft(struct seq_file *seq)
{
	return of_rft(seq->private);
}

#endif
