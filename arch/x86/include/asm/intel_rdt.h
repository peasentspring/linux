#ifndef _ASM_X86_INTEL_RDT_H
#define _ASM_X86_INTEL_RDT_H

/**
 * struct rdt_resource - attributes of an RDT resource
 * @enabled:			Is this feature enabled on this machine
 * @name:			Name to use in "schemata" file
 * @max_closid:			Maximum number of CLOSIDs supported
 * @num_closid:			Current number of CLOSIDs available
 * @max_cbm:			Largest Cache Bit Mask allowed
 * @min_cbm_bits:		Minimum number of bits to be set in a cache
 *				bit mask
 * @domains:			All domains for this resource
 * @num_domains:		Number of domains active
 * @msr_base:			Base MSR address for CBMs
 * @cdp_capable:		Code/Data Prioritization available
 * @cdp_enabled:		Code/Data Prioritization enabled
 * @tmp_cbms:			Scratch space when updating schemata
 * @cache_level:		Which cache level defines scope of this domain
 */
struct rdt_resource {
	bool			enabled;
	char			*name;
	int			max_closid;
	int			num_closid;
	int			cbm_len;
	int			min_cbm_bits;
	u32			max_cbm;
	struct list_head	domains;
	int			num_domains;
	int			msr_base;
	bool			cdp_capable;
	bool			cdp_enabled;
	u32			*tmp_cbms;
	int			cache_level;
};

#define for_each_rdt_resource(r)	\
	for (r = rdt_resources_all; r->name; r++) \
		if (r->enabled)

#define IA32_L3_CBM_BASE	0xc90
extern struct rdt_resource rdt_resources_all[];

enum {
	RDT_RESOURCE_L3,
};

/* Maximum CLOSID allowed across all enabled resoources */
extern int rdt_max_closid;

/* CPUID.(EAX=10H, ECX=ResID=1).EAX */
union cpuid_0x10_1_eax {
	struct {
		unsigned int cbm_len:5;
	} split;
	unsigned int full;
};

/* CPUID.(EAX=10H, ECX=ResID=1).EDX */
union cpuid_0x10_1_edx {
	struct {
		unsigned int cos_max:16;
	} split;
	unsigned int full;
};
#endif /* _ASM_X86_INTEL_RDT_H */
