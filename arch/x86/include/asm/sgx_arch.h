// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.
//
// Contains the architectural data structures used by the CPU to implement SGX.
// The data structures defined to be used by the Linux software stack should not
// be placed here.

#ifndef _ASM_X86_SGX_ARCH_H
#define _ASM_X86_SGX_ARCH_H

#include <linux/types.h>

#define SGX_CPUID 0x12

enum sgx_cpuid_leaves {
	SGX_CPUID_CAPABILITIES	= 0,
	SGX_CPUID_ATTRIBUTES	= 1,
	SGX_CPUID_EPC_BANKS	= 2,
};

/**
 * enum sgx_encls_leaves - ENCLS leaf functions
 * %ECREATE:	Create an enclave.
 * %EADD:	Add a page to an enclave.
 * %EINIT:	Launch an enclave.
 * %EREMOVE:	Remove a page from an enclave.
 * %EDBGRD:	Read a word from an enclve (peek).
 * %EDBGWR:	Write a word to an enclave (poke).
 * %EEXTEND:	Measure 256 bytes of an added enclave page.
 * %ELDB:	Load a swapped page in blocked state.
 * %ELDU:	Load a swapped page in unblocked state.
 * %EBLOCK:	Change page state to blocked i.e. entering hardware threads
 *		cannot access it and create new TLB entries.
 * %EPA:	Create a Version Array (VA) page used to store version number
 *		for a swapped EPC page.
 * %EWB:	Swap an enclave page to the regular memory. Checks that all
 *		threads have exited that were in the previous shoot-down
 *		sequence.
 * %ETRACK:	Start a new shoot down sequence. Used to together with EBLOCK
 *		to make sure that a page is safe to swap.
 */
enum sgx_encls_leaves {
	ECREATE	= 0x0,
	EADD	= 0x1,
	EINIT	= 0x2,
	EREMOVE	= 0x3,
	EDGBRD	= 0x4,
	EDGBWR	= 0x5,
	EEXTEND	= 0x6,
	ELDB	= 0x7,
	ELDU	= 0x8,
	EBLOCK	= 0x9,
	EPA	= 0xA,
	EWB	= 0xB,
	ETRACK	= 0xC,
	EAUG	= 0xD,
	EMODPR	= 0xE,
	EMODT	= 0xF,
};

#define SGX_MODULUS_SIZE 384

/**
 * enum sgx_misc_select - additional information to an SSA frame
 * %SGX_MISC_EXINFO:	Report #PF or #GP to the SSA frame.
 *
 * Save State Area (SSA) is a stack inside the enclave used to store processor
 * state when an exception or interrupt occurs. This enum defines additional
 * information stored to an SSA frame.
 */
enum sgx_misc_select {
	SGX_MISC_EXINFO		= 0x01,
};

#define SGX_MISC_RESERVED_MASK 0xFFFFFFFFFFFFFFFEL

#define SGX_SSA_GPRS_SIZE		182
#define SGX_SSA_MISC_EXINFO_SIZE	16

/**
 * enum sgx_attributes - attributes that define enclave privileges.
 * %SGX_ATTR_DEBUG:		Allow ENCLS(EDBGRD) and ENCLS(EDBGWR).
 * %SGX_ATTR_MODE64BIT:		Tell that this a 64-bit enclave.
 * %SGX_ATTR_PROVISIONKEY:      Allow to use provisioning keys used in the
 *				remote attestation.
 * %SGX_EINITTOKENKEY:		Allow to use token signing key used to allow to
 *				run enclaves.
 */
enum sgx_attribute {
	SGX_ATTR_DEBUG		= 0x02,
	SGX_ATTR_MODE64BIT	= 0x04,
	SGX_ATTR_PROVISIONKEY	= 0x10,
	SGX_ATTR_EINITTOKENKEY	= 0x20,
};

#define SGX_ATTR_RESERVED_MASK 0xFFFFFFFFFFFFFFC9L

#define SGX_SECS_RESERVED1_SIZE 24
#define SGX_SECS_RESERVED2_SIZE 32
#define SGX_SECS_RESERVED3_SIZE 96
#define SGX_SECS_RESERVED4_SIZE 3836

/**
 * struct sgx_secs - SGX Enclave Control Structure (SECS)
 * @size:		size of the address space
 * @base:		base address of the  address space
 * @ssa_frame_size:	size of an SSA frame
 * @misc_select:	additional information stored to an SSA frame
 * @attributes:		attributes for enclave
 * @xfrm:		XSave-Feature Request Mask, allowed subset of XCR0
 * @mrenclave:		SHA256-hash of the enclave page
 * @mrsigner:		SHA256-hash of the public key used to sign SIGSTRUCT
 * @product_id:		a user-defined value that is used in key derivation by
 *			ENCLU(EGETKEY)
 * @version:		a user-defined value that is used in key derivation by
 *			ENCLU(EGETKEY)
 *
 * SGX Enclave Control Structure (SECS) is a special enclave page that is not
 * visible in the address space. In fact, this structure defines the address
 * range and other global attributes for the enclave and it is the first EPC
 * page created for any enclave. It is moved from a temporary buffer to an EPC
 * by the means of ENCLS(ECREATE) leaf.
 */
struct sgx_secs {
	uint64_t size;
	uint64_t base;
	uint32_t ssa_frame_size;
	uint32_t misc_select;
	uint8_t  reserved1[SGX_SECS_RESERVED1_SIZE];
	uint64_t attributes;
	uint64_t xfrm;
	uint32_t mrenclave[8];
	uint8_t  reserved2[SGX_SECS_RESERVED2_SIZE];
	uint32_t mrsigner[8];
	uint8_t	 reserved3[SGX_SECS_RESERVED3_SIZE];
	uint16_t product_id;
	uint16_t version;
	uint8_t  reserved4[SGX_SECS_RESERVED4_SIZE];
} __packed;

/**
 * enum sgx_tcs_flags - execution flags for TCS
 * %SGX_TCS_DBGOPTIN:	If enabled allows single-stepping and breakpoints
 *			inside an enclave. It is cleared by EADD but can
 *			be set later with EDBGWR.
 */
enum sgx_tcs_flags {
	SGX_TCS_DBGOPTIN	= 0x01,
};

#define SGX_TCS_RESERVED_MASK 0xFFFFFFFFFFFFFFFEL
#define SGX_TCS_RESERVED_SIZE 503

/**
 * struct sgx_tcs - Thread Control Structure (TCS)
 * @state:		used to mark an entered TCS
 * @flags:		execution flags (cleared by EADD)
 * @ssa_offset:		SSA stack offset relative to the enclave base
 * @ssa_index:		the current SSA frame index (cleard by EADD)
 * @nr_ssa_frames:	the number of frame in the SSA stack
 * @entry_offset:	entry point offset relative to the enclave base
 * @exit_addr:		address outside the enclave to exit on an exception or
 *			interrupt
 * @fs_offset:		offset relative to the enclave base to become FS
 *			segment inside the enclave
 * @gs_offset:		offset relative to the enclave base to become GS
 *			segment inside the enclave
 * @fs_limit:		size to become a new FS-limit (only 32-bit enclaves)
 * @gs_limit:		size to become a new GS-limit (only 32-bit enclaves)
 *
 * Thread Control Structure (TCS) is an enclave page visible in its address
 * space that defines an entry point inside the enclave. A thread enters inside
 * an enclave by supplying address of TCS to ENCLU(EENTER). A TCS can be entered
 * by only one thread at a time.
 */
struct sgx_tcs {
	uint64_t state;
	uint64_t flags;
	uint64_t ssa_offset;
	uint32_t ssa_index;
	uint32_t nr_ssa_frames;
	uint64_t entry_offset;
	uint64_t exit_addr;
	uint64_t fs_offset;
	uint64_t gs_offset;
	uint32_t fs_limit;
	uint32_t gs_limit;
	uint64_t reserved[SGX_TCS_RESERVED_SIZE];
} __packed;

struct sgx_pageinfo {
	uint64_t linaddr;
	uint64_t srcpge;
	union {
		uint64_t secinfo;
		uint64_t pcmd;
	};
	uint64_t secs;
} __packed __aligned(32);


#define SGX_SECINFO_PERMISSION_MASK	0x0000000000000007L
#define SGX_SECINFO_PAGE_TYPE_MASK	0x000000000000FF00L
#define SGX_SECINFO_RESERVED_MASK	0xFFFFFFFFFFFF00F8L

enum sgx_page_type {
	SGX_PAGE_TYPE_SECS	= 0x00,
	SGX_PAGE_TYPE_TCS	= 0x01,
	SGX_PAGE_TYPE_REG	= 0x02,
	SGX_PAGE_TYPE_VA	= 0x03,
	SGX_PAGE_TYPE_TRIM	= 0x04,
};

enum sgx_secinfo_flags {
	SGX_SECINFO_R		= 0x01,
	SGX_SECINFO_W		= 0x02,
	SGX_SECINFO_X		= 0x04,
	SGX_SECINFO_SECS	= (SGX_PAGE_TYPE_SECS << 8),
	SGX_SECINFO_TCS		= (SGX_PAGE_TYPE_TCS << 8),
	SGX_SECINFO_REG		= (SGX_PAGE_TYPE_REG << 8),
	SGX_SECINFO_VA          = (SGX_PAGE_TYPE_VA << 8),
	SGX_SECINFO_TRIM	= (SGX_PAGE_TYPE_TRIM << 8),
};

#define SGX_SECINFO_RESERVED_SIZE 56

struct sgx_secinfo {
	uint64_t flags;
	uint8_t reserved[SGX_SECINFO_RESERVED_SIZE];
} __packed __aligned(64);

#define SGX_PCMD_RESERVED_SIZE 40

struct sgx_pcmd {
	struct sgx_secinfo secinfo;
	uint64_t enclave_id;
	uint8_t reserved[SGX_PCMD_RESERVED_SIZE];
	uint8_t mac[16];
} __packed __aligned(128);

#define SGX_SIGSTRUCT_RESERVED1_SIZE 84
#define SGX_SIGSTRUCT_RESERVED2_SIZE 20
#define SGX_SIGSTRUCT_RESERVED3_SIZE 32
#define SGX_SIGSTRUCT_RESERVED4_SIZE 12

struct sgx_sigstruct_header {
	uint64_t header1[2];
	uint32_t vendor;
	uint32_t date;
	uint64_t header2[2];
	uint32_t swdefined;
	uint8_t reserved1[SGX_SIGSTRUCT_RESERVED1_SIZE];
} __packed;

struct sgx_sigstruct_body {
	uint32_t miscselect;
	uint32_t miscmask;
	uint8_t reserved2[SGX_SIGSTRUCT_RESERVED2_SIZE];
	uint64_t attributes;
	uint64_t xfrm;
	uint8_t attributemask[16];
	uint8_t mrenclave[32];
	uint8_t reserved3[SGX_SIGSTRUCT_RESERVED3_SIZE];
	uint16_t isvprodid;
	uint16_t isvsvn;
} __packed;

struct sgx_sigstruct {
	struct sgx_sigstruct_header header;
	uint8_t modulus[SGX_MODULUS_SIZE];
	uint32_t exponent;
	uint8_t signature[SGX_MODULUS_SIZE];
	struct sgx_sigstruct_body body;
	uint8_t reserved4[SGX_SIGSTRUCT_RESERVED4_SIZE];
	uint8_t q1[SGX_MODULUS_SIZE];
	uint8_t q2[SGX_MODULUS_SIZE];
} __packed __aligned(4096);

#define SGX_EINITTOKEN_RESERVED1_SIZE 11
#define SGX_EINITTOKEN_RESERVED2_SIZE 32
#define SGX_EINITTOKEN_RESERVED3_SIZE 32
#define SGX_EINITTOKEN_RESERVED4_SIZE 24

struct sgx_einittoken_payload {
	uint32_t valid;
	uint32_t reserved1[SGX_EINITTOKEN_RESERVED1_SIZE];
	uint64_t attributes;
	uint64_t xfrm;
	uint8_t mrenclave[32];
	uint8_t reserved2[SGX_EINITTOKEN_RESERVED2_SIZE];
	uint8_t mrsigner[32];
	uint8_t reserved3[SGX_EINITTOKEN_RESERVED3_SIZE];
} __packed;

struct sgx_einittoken {
	struct sgx_einittoken_payload payload;
	uint8_t cpusvnle[16];
	uint16_t isvprodidle;
	uint16_t isvsvnle;
	uint8_t reserved4[SGX_EINITTOKEN_RESERVED4_SIZE];
	uint32_t maskedmiscselectle;
	uint64_t maskedattributesle;
	uint64_t maskedxfrmle;
	uint8_t keyid[32];
	uint8_t mac[16];
} __packed __aligned(512);

#endif /* _ASM_X86_SGX_ARCH_H */
