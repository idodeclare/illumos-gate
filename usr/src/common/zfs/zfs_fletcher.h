/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2013 Saso Kiselkov. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#ifndef	_ZFS_FLETCHER_H
#define	_ZFS_FLETCHER_H

#include <sys/types.h>
#include <sys/spa_checksum.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * fletcher checksum functions
 *
 * Note: Fletcher checksum methods expect buffer size to be 4B aligned. This
 * limitation stems from the algorithm design. Performing incremental checksum
 * without said alignment would yield different results. Therefore, the code
 * includes assertions for the size alignment.
 * For compatibility, it is required that some code paths calculate checksum of
 * non-aligned buffer sizes. For this purpose, `fletcher_4_native_varsize()`
 * checksum method is added. This method will ignore last (size % 4) bytes of
 * the data buffer.
 */

void fletcher_init(zio_cksum_t *);
void fletcher_2_native(const void *, size_t, const void *, zio_cksum_t *);
void fletcher_2_byteswap(const void *, size_t, const void *, zio_cksum_t *);
int fletcher_2_incremental_native(void *, size_t, void *);
int fletcher_2_incremental_byteswap(void *, size_t, void *);
void fletcher_4_native(const void *, size_t, const void *, zio_cksum_t *);
void fletcher_4_native_varsize(const void *, size_t, zio_cksum_t *);
void fletcher_4_byteswap(const void *, size_t, const void *, zio_cksum_t *);
int fletcher_4_incremental_native(void *, size_t, void *);
int fletcher_4_incremental_byteswap(void *, size_t, void *);
int fletcher_4_impl_set(const char *selector);
void fletcher_4_init(void);
void fletcher_4_fini(void);

/* Internal fletcher ctx */

typedef struct zfs_fletcher_superscalar {
	uint64_t v[4];
} zfs_fletcher_superscalar_t;

typedef struct zfs_fletcher_sse {
	uint64_t v[2];
} zfs_fletcher_sse_t;

typedef struct zfs_fletcher_avx {
	uint64_t v[4];
} zfs_fletcher_avx_t;

typedef struct zfs_fletcher_avx512 {
	uint64_t v[8];
} zfs_fletcher_avx512_t;

typedef union fletcher_4_ctx {
	zio_cksum_t scalar;
	zfs_fletcher_superscalar_t superscalar[4];
#ifdef __amd64
	zfs_fletcher_sse_t sse[4];
	zfs_fletcher_avx_t avx[4];
	zfs_fletcher_avx512_t avx512[4];
#endif
} fletcher_4_ctx_t;

/*
 * fletcher checksum struct
 */
typedef void (*fletcher_4_init_f)(fletcher_4_ctx_t *);
typedef void (*fletcher_4_fini_f)(fletcher_4_ctx_t *, zio_cksum_t *);
typedef void (*fletcher_4_compute_f)(fletcher_4_ctx_t *,
    const void *, size_t);

typedef struct fletcher_4_func {
	fletcher_4_init_f init_native;
	fletcher_4_fini_f fini_native;
	fletcher_4_compute_f compute_native;
	fletcher_4_init_f init_byteswap;
	fletcher_4_fini_f fini_byteswap;
	fletcher_4_compute_f compute_byteswap;
	boolean_t (*valid)(void);
	boolean_t uses_fpu_native;
	boolean_t uses_fpu_byteswap;
	const char *name;
} __attribute__((aligned(64))) fletcher_4_ops_t;

extern const fletcher_4_ops_t fletcher_4_superscalar_ops;
extern const fletcher_4_ops_t fletcher_4_superscalar4_ops;
#ifdef __amd64
extern const fletcher_4_ops_t fletcher_4_avx2_ops;
extern const fletcher_4_ops_t fletcher_4_sse2_ops;
extern const fletcher_4_ops_t fletcher_4_ssse3_ops;
extern const fletcher_4_ops_t fletcher_4_avx512f_ops;
extern const fletcher_4_ops_t fletcher_4_avx512bw_ops;
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _ZFS_FLETCHER_H */
