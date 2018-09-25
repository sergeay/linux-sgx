// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/mempolicy.h>
#include "sgx.h"

#define nmask_cpy(dst, orig) bitmap_copy((dst)->bits, (orig)->bits \
				, MAX_NUMNODES)

/**
 *	Computes the nearest node to node 'n' among all the sgx nodes,
 *	not including node 'n'. If 'n' is -1, the first sgx node in
 *	the mask is returned.
 *	Side effect: mask bits of non sgx nodes are cleared.
 */
static inline int get_near_sgx_node(nodemask_t *mask, int n)
{
	struct sgx_epc_node *node;
	int neigh, i = 0;

	if (-1 == n) {
		neigh = first_node(*mask);
		do {
			if (NODE_HAS_SGX(neigh))
				return neigh;
			neigh = next_node(neigh, *mask);
		} while (neigh != MAX_NUMNODES);
		return -1;
	}

	node = SGX_NODE_DATA(n);
	while (-1 != (neigh = node->near_list[i])) {
		if (!node_isset(i, *mask)) {
			i++;
			continue;
		}

		if (NODE_HAS_SGX(neigh))
			return neigh;

		node_clear(i, *mask);
		i++;
	}

	return -1;
}

/**
 *	Computes the nearest node to node 'n' among all the sgx nodes,
 *	including node 'n'.
 */
static inline int get_closest_sgx_node(nodemask_t *mask, int n)
{
	if (-1 != n && NODE_HAS_SGX(n))
		return n;

	return get_near_sgx_node(mask, n);
}

static void get_policy_node_and_mask(struct mempolicy *pol,
		struct vm_area_struct *vma, unsigned long addr,
		unsigned int *nid, nodemask_t **mask)
{
	*nid = -1;
	*mask = NULL;

	WARN_ON(!pol);

	if (pol->mode == MPOL_LOCAL ||
		(pol->mode == MPOL_PREFERRED && pol->flags & MPOL_F_LOCAL)) {
		*nid = numa_node_id();
		return;
	}

	/*	The round robin strategy is static and based on the address */
	if (pol->mode == MPOL_INTERLEAVE) {
		unsigned long off = (addr - vma->vm_start) >> PAGE_SHIFT;

		*nid = offset_il_node(pol, off);
		return;
	}

	if (pol->mode == MPOL_PREFERRED)
		*nid = pol->v.preferred_node;

	if (pol->mode == MPOL_BIND)
		*mask = &pol->v.nodes;
}

static struct sgx_epc_page *sgx_alloc_page_mask(struct sgx_epc_page_impl *impl,
		unsigned int flags, int nid, nodemask_t *mask, int policy_mode)
{
	struct sgx_epc_page *epc_page = ERR_PTR(-ENOMEM);
	unsigned int aflags = flags | SGX_ALLOC_ATOMIC;
	unsigned int nnode;
	int node, n, n0;
	nodemask_t node_mask;

	WARN_ON(policy_mode == MPOL_INTERLEAVE);

	/* local and preferred policies go first to the nid node */
	if (policy_mode == MPOL_PREFERRED || policy_mode == MPOL_LOCAL) {
		epc_page = sgx_alloc_page(impl, aflags, nid);
		if (!IS_ERR(epc_page))
			return epc_page;
	}

	nodes_setall(node_mask);
	if (policy_mode == MPOL_BIND) {
		nid = -1;
		nmask_cpy(&node_mask, mask);
	}

	nnode = nodes_weight(node_mask);
	node = get_near_sgx_node(&node_mask, nid);
	n0 = get_closest_sgx_node(&node_mask, nid);
	for (n = 0; n < nnode; node = get_near_sgx_node(&node_mask, nid), n++) {
		if (-1 == node)
			break;
		node_clear(node, node_mask);
		epc_page = sgx_alloc_page(impl, aflags, node);
		if (!IS_ERR(epc_page))
			return epc_page;
	}

	/* Fast allocation has failed. If this was not required then
	 *	allocate from slow path
	 */
	if (aflags != flags && -1 != n0)
		return sgx_alloc_page(impl, flags, n0);

	return epc_page;
}

struct sgx_epc_page *sgx_alloc_page_vma(struct sgx_epc_page_impl *impl,
					unsigned int flags, unsigned long addr,
					struct vm_area_struct *vma)
{
	int nid;
	struct mempolicy *pol;
	struct sgx_epc_page *epc_page;
	nodemask_t *nmask;

	pol = get_vma_policy(vma, addr);
	get_policy_node_and_mask(pol, vma, addr, &nid, &nmask);


	if (pol->mode == MPOL_INTERLEAVE) {
		if (!(flags & SGX_ALLOC_ATOMIC))
			up_read(&vma->vm_mm->mmap_sem);
		mpol_cond_put(pol);
		return sgx_alloc_page(impl, flags, nid);
	}

	if (!(flags & SGX_ALLOC_ATOMIC))
		up_read(&vma->vm_mm->mmap_sem);

	/* local, bind and preferred policy cases */
	epc_page = sgx_alloc_page_mask(impl, flags, nid, nmask, pol->mode);
	mpol_cond_put(pol);
	return epc_page;
}

struct sgx_epc_page *sgx_alloc_page_mm(struct sgx_epc_page_impl *impl,
				unsigned long addr,	struct mm_struct *mm)
{
	struct vm_area_struct *vma;

	down_read(&mm->mmap_sem);
	vma = find_vma(mm, addr);
	if (!vma) {
		up_read(&mm->mmap_sem);
		return ERR_PTR(-EBUSY);  // TBD
	}

	return sgx_alloc_page_vma(impl, 0, addr, vma);
}

