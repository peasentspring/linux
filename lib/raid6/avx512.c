/* -*- linux-c -*- --------------------------------------------------------
 *
 *   Copyright (C) 2016 Intel Corporation
 *
 *   Author: Gayatri Kammela <gayatri.kammela@intel.com>
 *   Author: Megha Dey <megha.dey@linux.intel.com>
 *
 *   Based on avx2.c: Copyright 2012 Yuanhan Liu All Rights Reserved
 *   Based on sse2.c: Copyright 2002 H. Peter Anvin - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 53 Temple Place Ste 330,
 *   Boston MA 02111-1307, USA; either version 2 of the License, or
 *   (at your option) any later version; incorporated herein by reference.
 *
 * -----------------------------------------------------------------------
 */

/*
 * AVX512 implementation of RAID-6 syndrome functions
 *
 */

#ifdef CONFIG_AS_AVX512

#include <linux/raid/pq.h>
#include "x86.h"

static const struct raid6_avx512_constants {
	u64 x1d[8];
} raid6_avx512_constants __aligned(512) = {
	{ 0x1d1d1d1d1d1d1d1dULL, 0x1d1d1d1d1d1d1d1dULL,
	  0x1d1d1d1d1d1d1d1dULL, 0x1d1d1d1d1d1d1d1dULL,
	  0x1d1d1d1d1d1d1d1dULL, 0x1d1d1d1d1d1d1d1dULL,
	  0x1d1d1d1d1d1d1d1dULL, 0x1d1d1d1d1d1d1d1dULL,},
};

static int raid6_have_avx512(void)
{
	return boot_cpu_has(X86_FEATURE_AVX2) &&
		boot_cpu_has(X86_FEATURE_AVX) &&
		boot_cpu_has(X86_FEATURE_AVX512F) &&
		boot_cpu_has(X86_FEATURE_AVX512BW) &&
		boot_cpu_has(X86_FEATURE_AVX512VL) &&
		boot_cpu_has(X86_FEATURE_AVX512DQ);
}

static void raid6_avx5121_gen_syndrome(int disks, size_t bytes, void **ptrs)
{
	u8 **dptr = (u8 **)ptrs;
	u8 *p, *q;
	int d, z, z0;

	z0 = disks - 3;         /* Highest data disk */
	p = dptr[z0+1];         /* XOR parity */
	q = dptr[z0+2];         /* RS syndrome */

	kernel_fpu_begin();

	asm volatile("vmovdqa64 %0,%%zmm0"
		     : : "m" (raid6_avx512_constants.x1d[0]));
	asm volatile("vpxorq %zmm1,%zmm1,%zmm1"); /* Zero temp */

	for (d = 0; d < bytes; d += 64) {
		asm volatile("prefetchnta %0" : : "m" (dptr[z0][d]));
		asm volatile("vmovdqa64 %0,%%zmm2"
			     : : "m" (dptr[z0][d]));/* P[0] */
		asm volatile("prefetchnta %0" : : "m" (dptr[z0-1][d]));
		asm volatile("vmovdqa64 %zmm2,%zmm4");/* Q[0] */
		asm volatile("vmovdqa64 %0,%%zmm6" : : "m" (dptr[z0-1][d]));
		for (z = z0-2; z >= 0; z--) {
			asm volatile("prefetchnta %0" : : "m" (dptr[z][d]));
			asm volatile("vpcmpgtb %zmm4,%zmm1,%k1");
			asm volatile("vpmovm2b %k1,%zmm5");
			asm volatile("vpaddb %zmm4,%zmm4,%zmm4");
			asm volatile("vpandq %zmm0,%zmm5,%zmm5");
			asm volatile("vpxorq %zmm5,%zmm4,%zmm4");
			asm volatile("vpxorq %zmm6,%zmm2,%zmm2");
			asm volatile("vpxorq %zmm6,%zmm4,%zmm4");
			asm volatile("vmovdqa64 %0,%%zmm6"
				     : : "m" (dptr[z][d]));
		}
			asm volatile("vpcmpgtb %zmm4,%zmm1,%k1");
			asm volatile("vpmovm2b %k1,%zmm5");
			asm volatile("vpaddb %zmm4,%zmm4,%zmm4");
			asm volatile("vpandq %zmm0,%zmm5,%zmm5");
			asm volatile("vpxorq %zmm5,%zmm4,%zmm4");
			asm volatile("vpxorq %zmm6,%zmm2,%zmm2");
			asm volatile("vpxorq %zmm6,%zmm4,%zmm4");

		asm volatile("vmovntdq %%zmm2,%0" : "=m" (p[d]));
		asm volatile("vpxorq %zmm2,%zmm2,%zmm2");
		asm volatile("vmovntdq %%zmm4,%0" : "=m" (q[d]));
		asm volatile("vpxorq %zmm4,%zmm4,%zmm4");
	}

	asm volatile("sfence" : : : "memory");
	kernel_fpu_end();
}

const struct raid6_calls raid6_avx512x1 = {
	raid6_avx5121_gen_syndrome,
	NULL,                   /* XOR not yet implemented */
	raid6_have_avx512,
	"avx512x1",
	1                       /* Has cache hints */
};

/*
 * Unrolled-by-2 AVX512 implementation
 */
static void raid6_avx5122_gen_syndrome(int disks, size_t bytes, void **ptrs)
{
	u8 **dptr = (u8 **)ptrs;
	u8 *p, *q;
	int d, z, z0;

	z0 = disks - 3;         /* Highest data disk */
	p = dptr[z0+1];         /* XOR parity */
	q = dptr[z0+2];         /* RS syndrome */

	kernel_fpu_begin();

	asm volatile("vmovdqa64 %0,%%zmm0"
		     : : "m" (raid6_avx512_constants.x1d[0]));
	asm volatile("vpxorq %zmm1,%zmm1,%zmm1"); /* Zero temp */

	/* We uniformly assume a single prefetch covers at least 64 bytes */
	for (d = 0; d < bytes; d += 128) {
		asm volatile("prefetchnta %0" : : "m" (dptr[z0][d]));
		asm volatile("prefetchnta %0" : : "m" (dptr[z0][d+64]));
		asm volatile("vmovdqa64 %0,%%zmm2"
			     : : "m" (dptr[z0][d]));/* P[0] */
		asm volatile("vmovdqa64 %0,%%zmm3"
			     : : "m" (dptr[z0][d+64]));/* P[1] */
		asm volatile("vmovdqa64 %zmm2,%zmm4"); /* Q[0] */
		asm volatile("vmovdqa64 %zmm3,%zmm6"); /* Q[1] */
		for (z = z0-1; z >= 0; z--) {
			asm volatile("prefetchnta %0" : : "m" (dptr[z][d]));
			asm volatile("prefetchnta %0" : : "m" (dptr[z][d+64]));
			asm volatile("vpcmpgtb %zmm4,%zmm1,%k1");
			asm volatile("vpcmpgtb %zmm6,%zmm1,%k2");
			asm volatile("vpmovm2b %k1,%zmm5");
			asm volatile("vpmovm2b %k2,%zmm7");
			asm volatile("vpaddb %zmm4,%zmm4,%zmm4");
			asm volatile("vpaddb %zmm6,%zmm6,%zmm6");
			asm volatile("vpandq %zmm0,%zmm5,%zmm5");
			asm volatile("vpandq %zmm0,%zmm7,%zmm7");
			asm volatile("vpxorq %zmm5,%zmm4,%zmm4");
			asm volatile("vpxorq %zmm7,%zmm6,%zmm6");
			asm volatile("vmovdqa64 %0,%%zmm5"
				     : : "m" (dptr[z][d]));
			asm volatile("vmovdqa64 %0,%%zmm7"
				     : : "m" (dptr[z][d+64]));
			asm volatile("vpxorq %zmm5,%zmm2,%zmm2");
			asm volatile("vpxorq %zmm7,%zmm3,%zmm3");
			asm volatile("vpxorq %zmm5,%zmm4,%zmm4");
			asm volatile("vpxorq %zmm7,%zmm6,%zmm6");
		}
		asm volatile("vmovntdq %%zmm2,%0" : "=m" (p[d]));
		asm volatile("vmovntdq %%zmm3,%0" : "=m" (p[d+64]));
		asm volatile("vmovntdq %%zmm4,%0" : "=m" (q[d]));
		asm volatile("vmovntdq %%zmm6,%0" : "=m" (q[d+64]));
	}

	asm volatile("sfence" : : : "memory");
	kernel_fpu_end();
}

const struct raid6_calls raid6_avx512x2 = {
	raid6_avx5122_gen_syndrome,
	NULL,                   /* XOR not yet implemented */
	raid6_have_avx512,
	"avx512x2",
	1                       /* Has cache hints */
};

#ifdef CONFIG_X86_64

/*
 * Unrolled-by-4 AVX2 implementation
 */
static void raid6_avx5124_gen_syndrome(int disks, size_t bytes, void **ptrs)
{
	u8 **dptr = (u8 **)ptrs;
	u8 *p, *q;
	int d, z, z0;

	z0 = disks - 3;         /* Highest data disk */
	p = dptr[z0+1];         /* XOR parity */
	q = dptr[z0+2];         /* RS syndrome */

	kernel_fpu_begin();

	asm volatile("vmovdqa64 %0,%%zmm0"
		     : : "m" (raid6_avx512_constants.x1d[0]));
	asm volatile("vpxorq %zmm1,%zmm1,%zmm1");       /* Zero temp */
	asm volatile("vpxorq %zmm2,%zmm2,%zmm2");       /* P[0] */
	asm volatile("vpxorq %zmm3,%zmm3,%zmm3");       /* P[1] */
	asm volatile("vpxorq %zmm4,%zmm4,%zmm4");       /* Q[0] */
	asm volatile("vpxorq %zmm6,%zmm6,%zmm6");       /* Q[1] */
	asm volatile("vpxorq %zmm10,%zmm10,%zmm10");    /* P[2] */
	asm volatile("vpxorq %zmm11,%zmm11,%zmm11");    /* P[3] */
	asm volatile("vpxorq %zmm12,%zmm12,%zmm12");    /* Q[2] */
	asm volatile("vpxorq %zmm14,%zmm14,%zmm14");    /* Q[3] */

	for (d = 0; d < bytes; d += 256) {
		for (z = z0; z >= 0; z--) {
			asm volatile("prefetchnta %0" : : "m" (dptr[z][d]));
			asm volatile("prefetchnta %0" : : "m" (dptr[z][d+64]));
			asm volatile("prefetchnta %0" : : "m" (dptr[z][d+128]));
			asm volatile("prefetchnta %0" : : "m" (dptr[z][d+192]));
			asm volatile("vpcmpgtb %zmm4,%zmm1,%k1");
			asm volatile("vpcmpgtb %zmm6,%zmm1,%k2");
			asm volatile("vpcmpgtb %zmm12,%zmm1,%k3");
			asm volatile("vpcmpgtb %zmm14,%zmm1,%k4");
			asm volatile("vpmovm2b %k1,%zmm5");
			asm volatile("vpmovm2b %k2,%zmm7");
			asm volatile("vpmovm2b %k3,%zmm13");
			asm volatile("vpmovm2b %k4,%zmm15");
			asm volatile("vpaddb %zmm4,%zmm4,%zmm4");
			asm volatile("vpaddb %zmm6,%zmm6,%zmm6");
			asm volatile("vpaddb %zmm12,%zmm12,%zmm12");
			asm volatile("vpaddb %zmm14,%zmm14,%zmm14");
			asm volatile("vpandq %zmm0,%zmm5,%zmm5");
			asm volatile("vpandq %zmm0,%zmm7,%zmm7");
			asm volatile("vpandq %zmm0,%zmm13,%zmm13");
			asm volatile("vpandq %zmm0,%zmm15,%zmm15");
			asm volatile("vpxorq %zmm5,%zmm4,%zmm4");
			asm volatile("vpxorq %zmm7,%zmm6,%zmm6");
			asm volatile("vpxorq %zmm13,%zmm12,%zmm12");
			asm volatile("vpxorq %zmm15,%zmm14,%zmm14");
			asm volatile("vmovdqa64 %0,%%zmm5"
				     : : "m" (dptr[z][d]));
			asm volatile("vmovdqa64 %0,%%zmm7"
				     : : "m" (dptr[z][d+64]));
			asm volatile("vmovdqa64 %0,%%zmm13"
				     : : "m" (dptr[z][d+128]));
			asm volatile("vmovdqa64 %0,%%zmm15"
				     : : "m" (dptr[z][d+192]));
			asm volatile("vpxorq %zmm5,%zmm2,%zmm2");
			asm volatile("vpxorq %zmm7,%zmm3,%zmm3");
			asm volatile("vpxorq %zmm13,%zmm10,%zmm10");
			asm volatile("vpxorq %zmm15,%zmm11,%zmm11");
			asm volatile("vpxorq %zmm5,%zmm4,%zmm4");
			asm volatile("vpxorq %zmm7,%zmm6,%zmm6");
			asm volatile("vpxorq %zmm13,%zmm12,%zmm12");
			asm volatile("vpxorq %zmm15,%zmm14,%zmm14");
		}
		asm volatile("vmovntdq %%zmm2,%0" : "=m" (p[d]));
		asm volatile("vpxorq %zmm2,%zmm2,%zmm2");
		asm volatile("vmovntdq %%zmm3,%0" : "=m" (p[d+64]));
		asm volatile("vpxorq %zmm3,%zmm3,%zmm3");
		asm volatile("vmovntdq %%zmm10,%0" : "=m" (p[d+128]));
		asm volatile("vpxorq %zmm10,%zmm10,%zmm10");
		asm volatile("vmovntdq %%zmm11,%0" : "=m" (p[d+192]));
		asm volatile("vpxorq %zmm11,%zmm11,%zmm11");
		asm volatile("vmovntdq %%zmm4,%0" : "=m" (q[d]));
		asm volatile("vpxorq %zmm4,%zmm4,%zmm4");
		asm volatile("vmovntdq %%zmm6,%0" : "=m" (q[d+64]));
		asm volatile("vpxorq %zmm6,%zmm6,%zmm6");
		asm volatile("vmovntdq %%zmm12,%0" : "=m" (q[d+128]));
		asm volatile("vpxorq %zmm12,%zmm12,%zmm12");
		asm volatile("vmovntdq %%zmm14,%0" : "=m" (q[d+192]));
		asm volatile("vpxorq %zmm14,%zmm14,%zmm14");
	}

	asm volatile("sfence" : : : "memory");
	kernel_fpu_end();
}

const struct raid6_calls raid6_avx512x4 = {
	raid6_avx5124_gen_syndrome,
	NULL,                   /* XOR not yet implemented */
	raid6_have_avx512,
	"avx512x4",
	1                       /* Has cache hints */
};
#endif

#endif /* CONFIG_AS_AVX512 */
