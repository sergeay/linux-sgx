// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.

#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/nodemask.h>
#include <linux/numa.h>
#include <linux/pagemap.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/suspend.h>
#include <linux/wait.h>
#include <asm/sgx.h>
#include <asm/sgx_pr.h>

/**
 * enum sgx_swap_constants - the constants used by the swapping code
 * %SGX_NR_TO_SCAN:	the number of pages to scan in a single round
 * %SGX_NR_LOW_PAGES:	the low watermark for ksgxswapd when it starts to swap
 *			pages.
 * %SGX_NR_HIGH_PAGES:	the high watermark for ksgxswapd what it stops swapping
 *			pages.
 */
enum sgx_swap_constants {
	SGX_NR_TO_SCAN		= 16,
	SGX_NR_LOW_PAGES	= 32,
	SGX_NR_HIGH_PAGES	= 64,
};

bool sgx_enabled __ro_after_init;
EXPORT_SYMBOL_GPL(sgx_enabled);
bool sgx_lc_enabled __ro_after_init;
EXPORT_SYMBOL_GPL(sgx_lc_enabled);
struct sgx_epc_bank sgx_epc_banks[SGX_MAX_EPC_BANKS];
struct sgx_epc_node sgx_nodes[MAX_SGX_NUMNODES];
EXPORT_SYMBOL_GPL(sgx_nodes);

static int sgx_nr_epc_banks;
static struct notifier_block sgx_pm_notifier;
static u64 sgx_pm_cnt;

/* The cache for the last known values of IA32_SGXLEPUBKEYHASHx MSRs for each
 * CPU. The entries are initialized when they are first used by sgx_einit().
 */
struct sgx_lepubkeyhash {
	u64 msrs[4];
	u64 pm_cnt;
};

static DEFINE_PER_CPU(struct sgx_lepubkeyhash *, sgx_lepubkeyhash_cache);

/**
 * sgx_reclaim_pages - reclaim EPC pages from the consumers
 *
 * Takes a fixed chunk of pages from the global list of consumed EPC pages and
 * tries to swap them. Only the pages that are either being freed by the
 * consumer or actively used are skipped.
 */
static void sgx_reclaim_pages(struct sgx_epc_node *node)
{
	struct sgx_epc_page *chunk[SGX_NR_TO_SCAN + 1];
	struct sgx_epc_page *epc_page;
	int i, j;

	spin_lock(&node->active_page_list_lock);
	for (i = 0, j = 0; i < SGX_NR_TO_SCAN; i++) {
		if (is_active_list_empty(node))
			break;

		epc_page = get_active_list_first(node);
		remove_from_active_list(epc_page);

		if (epc_page->impl->ops->get(epc_page))
			chunk[j++] = epc_page;
		else
			epc_page->desc &= ~SGX_EPC_PAGE_RECLAIMABLE;
	}
	spin_unlock(&node->active_page_list_lock);

	for (i = 0; i < j; i++) {
		epc_page = chunk[i];
		if (epc_page->impl->ops->reclaim(epc_page))
			continue;

		spin_lock(&node->active_page_list_lock);
		return_to_active_list_tail(epc_page, node);
		spin_unlock(&node->active_page_list_lock);

		epc_page->impl->ops->put(epc_page);
		chunk[i] = NULL;
	}

	for (i = 0; i < j; i++) {
		epc_page = chunk[i];
		if (epc_page)
			epc_page->impl->ops->block(epc_page);
	}

	for (i = 0; i < j; i++) {
		epc_page = chunk[i];
		if (epc_page) {
			epc_page->impl->ops->write(epc_page);
			epc_page->impl->ops->put(epc_page);

			/*
			 * Put the page back on the free list only after we
			 * have put() our reference to the owner of the EPC
			 * page, otherwise the page could be re-allocated and
			 * we'd call put() on the wrong impl.
			 */
			epc_page->desc &= ~SGX_EPC_PAGE_RECLAIMABLE;

			spin_lock(&node->lock);
			node->pages[node->free_cnt++] = epc_page;
			spin_unlock(&node->lock);
		}
	}
}

static inline bool sgx_should_reclaim(struct sgx_epc_node *node)
{
	return node->free_cnt < SGX_NR_HIGH_PAGES &&
	       !is_active_list_empty(node);
}

static int ksgxswapd(void *p)
{
	struct sgx_epc_node *node = (struct sgx_epc_node *)p;

	set_freezable();

	while (!kthread_should_stop()) {
		if (try_to_freeze())
			continue;

		wait_event_freezable(node->kswapd_waitq,
			kthread_should_stop() || sgx_should_reclaim(node));

		if (sgx_should_reclaim(node))
			sgx_reclaim_pages(node);

		cond_resched();
	}

	return 0;
}

static struct sgx_epc_page *sgx_try_alloc_page(struct sgx_epc_page_impl *impl,
						struct sgx_epc_node *node)
{
	struct sgx_epc_page *page = NULL;

	if (!node->bank)
		return NULL;

	spin_lock(&node->lock);
	if (node->free_cnt) {
		page = node->pages[node->free_cnt - 1];
		node->free_cnt--;
	}
	spin_unlock(&node->lock);

	if (page) {
		page->impl = impl;
		return page;
	}

	return NULL;
}

/**
 * sgx_alloc_page - Allocate an EPC page
 * @flags:	allocation flags
 * @impl:	implementation for the EPC page
 *
 * Try to grab a page from the free EPC page list. If there is a free page
 * available, it is returned to the caller. If called with SGX_ALLOC_ATOMIC,
 * the function will return immediately if the list is empty. Otherwise, it
 * will swap pages up until there is a free page available. Upon returning the
 * low watermark is checked and ksgxswapd is waken up if we are below it.
 *
 * Return:
 *   a pointer to a &struct sgx_epc_page instace,
 *   -ENOMEM if all pages are unreclaimable,
 *   -EBUSY when called with SGX_ALLOC_ATOMIC and out of free pages
 */
struct sgx_epc_page *sgx_alloc_page(struct sgx_epc_page_impl *impl,
				    unsigned int flags, int nid)
{
	struct sgx_epc_page *entry;
	struct sgx_epc_node *node = SGX_NODE_DATA(nid);

	if (!node->bank)
		return ERR_PTR(-ENOMEM);

	for ( ; ; ) {
		entry = sgx_try_alloc_page(impl, node);
		if (entry)
			break;

		if (is_active_list_empty(node))
			return ERR_PTR(-ENOMEM);

		if (flags & SGX_ALLOC_ATOMIC) {
			entry = ERR_PTR(-EBUSY);
			break;
		}

		if (signal_pending(current)) {
			entry = ERR_PTR(-ERESTARTSYS);
			break;
		}

		sgx_reclaim_pages(node);
		schedule();
	}

	if (node->free_cnt < SGX_NR_LOW_PAGES)
		wake_up(&node->kswapd_waitq);

	return entry;
}
EXPORT_SYMBOL_GPL(sgx_alloc_page);

/**
 * __sgx_free_page - Free an EPC page
 * @page:	pointer a previously allocated EPC page
 *
 * EREMOVE an EPC page and insert it back to the list of free pages.
 * If the page is reclaimable, deletes it from the active page list.
 *
 * Return:
 *   0 on success
 *   -EBUSY if the page cannot be removed from the active list
 *   SGX error code if EREMOVE fails
 */
int __sgx_free_page(struct sgx_epc_page *page)
{
	struct sgx_epc_node *node = sgx_epc_node(page);
	int ret;

	/*
	 * Remove the page from the active list if necessary.  If the page
	 * is actively being reclaimed, i.e. RECLAIMABLE is set but the
	 * page isn't on the active list, return -EBUSY as we can't free
	 * the page at this time since it is "owned" by the reclaimer.
	 */
	if (page->desc & SGX_EPC_PAGE_RECLAIMABLE) {
		spin_lock(&node->active_page_list_lock);
		if (page->desc & SGX_EPC_PAGE_RECLAIMABLE) {
			if (list_empty(&page->list)) {
				spin_unlock(&node->active_page_list_lock);
				return -EBUSY;
			}
			list_del(&page->list);
			page->desc &= ~SGX_EPC_PAGE_RECLAIMABLE;
		}
		spin_unlock(&node->active_page_list_lock);
	}

	ret = __eremove(sgx_epc_addr(page));
	if (ret)
		return ret;

	spin_lock(&node->lock);
	node->pages[node->free_cnt++] = page;
	spin_unlock(&node->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(__sgx_free_page);

/**
 * sgx_free_page - Free an EPC page and WARN on failure
 * @page:	pointer to a previously allocated EPC page
 *
 * EREMOVE an EPC page and insert it back to the list of free pages.
 * If the page is reclaimable, deletes it from the active page list.
 * WARN on any failure.  For use when the call site cannot (or chooses
 * not to) handle failure, i.e. the page is leaked on failure.
 */
void sgx_free_page(struct sgx_epc_page *page)
{
	int ret;

	ret = __sgx_free_page(page);
	WARN(ret < 0, "sgx: cannot free page, reclaim in-progress");
	WARN(ret > 0, "sgx: EREMOVE returned %d (0x%x)", ret, ret);
}
EXPORT_SYMBOL_GPL(sgx_free_page);


/**
 * sgx_page_reclaimable - mark a page as reclaimable
 *
 * @page:	EPC page
 *
 * Mark a page as reclaimable and add it to the active page list.  Pages
 * are automatically removed from the active list when freed.
 */
void sgx_page_reclaimable(struct sgx_epc_page *page)
{
	struct sgx_epc_node *node = sgx_epc_node(page);

	spin_lock(&node->active_page_list_lock);
	page->desc |= SGX_EPC_PAGE_RECLAIMABLE;
	return_to_active_list_tail(page, node);
	spin_unlock(&node->active_page_list_lock);
}
EXPORT_SYMBOL_GPL(sgx_page_reclaimable);

struct page *sgx_get_backing(struct file *file, pgoff_t index)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct address_space *mapping = inode->i_mapping;
	gfp_t gfpmask = mapping_gfp_mask(mapping);

	return shmem_read_mapping_page_gfp(mapping, index, gfpmask);
}
EXPORT_SYMBOL_GPL(sgx_get_backing);

void sgx_put_backing(struct page *backing_page, bool write)
{
	if (write)
		set_page_dirty(backing_page);

	put_page(backing_page);
}
EXPORT_SYMBOL_GPL(sgx_put_backing);

/**
 * sgx_einit - initialize an enclave
 * @sigstruct:		a pointer to the SIGSTRUCT
 * @token:		a pointer to the EINITTOKEN
 * @secs_page:		a pointer to the SECS EPC page
 * @lepubkeyhash:	the desired value for IA32_SGXLEPUBKEYHASHx MSRs
 *
 * Try to perform EINIT operation. If the MSRs are writable, they are updated
 * according to @lepubkeyhash.
 *
 * Return:
 *   0 on success,
 *   -errno on failure
 *   SGX error code if EINIT fails
 */
int sgx_einit(struct sgx_sigstruct *sigstruct, struct sgx_einittoken *token,
	      struct sgx_epc_page *secs_page, u64 lepubkeyhash[4])
{
	struct sgx_lepubkeyhash __percpu *cache;
	bool cache_valid;
	int i, ret;

	if (!sgx_lc_enabled)
		return __einit(sigstruct, token, sgx_epc_addr(secs_page));

	cache = per_cpu(sgx_lepubkeyhash_cache, smp_processor_id());
	if (!cache) {
		cache = kzalloc(sizeof(struct sgx_lepubkeyhash), GFP_KERNEL);
		if (!cache)
			return -ENOMEM;
	}

	cache_valid = cache->pm_cnt == sgx_pm_cnt;
	cache->pm_cnt = sgx_pm_cnt;
	preempt_disable();
	for (i = 0; i < 4; i++) {
		if (cache_valid && lepubkeyhash[i] == cache->msrs[i])
			continue;

		wrmsrl(MSR_IA32_SGXLEPUBKEYHASH0 + i, lepubkeyhash[i]);
		cache->msrs[i] = lepubkeyhash[i];
	}
	ret = __einit(sigstruct, token, sgx_epc_addr(secs_page));
	preempt_enable();
	return ret;
}
EXPORT_SYMBOL(sgx_einit);

static __init int sgx_init_epc_bank(u64 addr, u64 size, unsigned long index,
									int nid)
{
	unsigned long nr_pages = size >> PAGE_SHIFT;
	struct sgx_epc_bank *bank = sgx_epc_banks + index;
	struct sgx_epc_node *node = SGX_NODE_DATA(nid);
	void *va;

	va = ioremap_cache(addr, size);
	if (!va)
		return -ENOMEM;

	/* there can not be more than one bank per node */
	WARN_ON(node->bank);
	node->bank = bank;
	node->free_cnt = nr_pages;

	bank->pa = addr;
	bank->size = size;
	bank->va = va;
	spin_lock_init(&node->lock);
	return 0;
}

static __init void sgx_page_cache_teardown(void)
{
	struct sgx_epc_node *node;
	int i;

	for_each_online_node(i) {
		node = SGX_NODE_DATA(i);
		kfree(node->near_list);
		node->near_list = NULL;
		if (!node->bank)
			continue;
		if (node->kswapd_tsk) {
			kthread_stop(node->kswapd_tsk);
			node->kswapd_tsk = NULL;
		}
		kfree(node->pages);
		kfree(node->pages_data);
		node->free_cnt = 0;
		node->bank = NULL;
	}

	for (i = 0; i < sgx_nr_epc_banks; i++)
		iounmap((void *)sgx_epc_banks[i].va);
}

static __init int sgx_init_epc_node(int nid)
{
	struct sgx_epc_node *node = SGX_NODE_DATA(nid);
	struct sgx_epc_bank *bank;
	unsigned long nr_pages = node->free_cnt;
	unsigned long addr;
	struct task_struct *tsk;
	char *kthname = "ksgxswapd0";
	int i;

	node->pages_data = kcalloc(nr_pages, sizeof(struct sgx_epc_page),
				   GFP_KERNEL);
	if (!node->pages_data)
		return -ENOMEM;

	spin_lock_init(&node->active_page_list_lock);
	INIT_LIST_HEAD(&node->active_page_list);

	node->pages = kcalloc(nr_pages, sizeof(struct sgx_epc_page *),
			      GFP_KERNEL);
	if (!node->pages) {
		kfree(node->pages_data);
		node->pages_data = NULL;
		return -ENOMEM;
	}

	bank = node->bank;
	for (i = 0, addr = bank->pa; i < nr_pages; i++, addr += PAGE_SIZE) {
		if (addr >= bank->pa + bank->size) {
			bank++;
			addr = bank->pa;
		}
		node->pages[i] = &node->pages_data[i];
		node->pages[i]->desc = addr | nid;
	}

	node->nr_total_pages = nr_pages;
	spin_lock_init(&node->lock);
	init_waitqueue_head(&node->kswapd_waitq);
	kthname[9] += nid;
	tsk = kthread_run(ksgxswapd, (void *)node, kthname);
	if (IS_ERR(tsk)) {
		sgx_page_cache_teardown();
		return PTR_ERR(tsk);
	}
	node->kswapd_tsk = tsk;

	pr_debug("node %d: %ld sgx pages", nid, nr_pages);
	return 0;
}

unsigned long get_total_sgx_mem(int i)
{
	struct sgx_epc_node *node = SGX_NODE_DATA(i);

	return node->nr_total_pages << PAGE_SHIFT;
}
EXPORT_SYMBOL(get_total_sgx_mem);

unsigned long get_free_sgx_mem(int i)
{
	struct sgx_epc_node *node = SGX_NODE_DATA(i);

	return node->free_cnt << PAGE_SHIFT;
}
EXPORT_SYMBOL(get_free_sgx_mem);

static int address_to_node(unsigned long addr)
{
	int n;

	for_each_online_node(n) {
		if (addr >= PFN_PHYS(node_start_pfn(n)) &&
			addr < PFN_PHYS(node_end_pfn(n)))
			return n;
	}

	return -1;
}

/**
 *	Returns the closest SGX node to node n
 *	with corresponding bit in *mask set
 */
static int find_best_sgx_node(int n, nodemask_t *mask)
{
	int nn, best = -1;
	unsigned int dist = -1, d;

	for_each_online_node(nn) {
		if (n == nn)
			continue;
		if (!node_isset(nn, *mask))
			continue;
		if (!NODE_HAS_SGX(nn))
			continue;
		d = node_distance(n, nn);
		if (d < dist) {
			best = nn;
			dist = d;
		}
	}

	return best;
}

static int sgx_nodes_init(void)
{
	int n, i, ret, nn;
	int nr_sgx_nodes = 0;
	nodemask_t nmask;
	struct sgx_epc_node *node;

	for_each_online_node(n) {
		if (!NODE_HAS_SGX(n))
			continue;

		ret = sgx_init_epc_node(n);
		if (ret)
			return ret;

		nr_sgx_nodes++;
	}

	for_each_online_node(n) {
		nodes_setall(nmask);
		node = SGX_NODE_DATA(n);
		node->near_list = kcalloc((1+nr_sgx_nodes),
			sizeof(int), GFP_KERNEL);
		if (!node->near_list)
			return -ENOMEM;

		i = 0;
		while (-1 != (nn = find_best_sgx_node(n, &nmask))) {
			node->near_list[i] = nn;
			node_clear(nn, nmask);
			i++;
		}
		node->near_list[i] = -1;
	}

	return 0;
}

static unsigned long get_epc_bank_range(int n, u64 *pa)
{
	unsigned int eax;
	unsigned int ebx;
	unsigned int ecx;
	unsigned int edx;

	cpuid_count(SGX_CPUID, n + 2, &eax, &ebx,
			&ecx, &edx);
	if (!(eax & 0xf))
		return -1;

	*pa = ((u64)(ebx & 0xfffff) << 32) + (u64)(eax & 0xfffff000);
	return ((u64)(edx & 0xfffff) << 32) + (u64)(ecx & 0xfffff000);
}

static inline u64 sgx_combine_bank_regs(u64 low, u64 high)
{
	return (low & 0xFFFFF000) + ((high & 0xFFFFF) << 32);
}

static __init int sgx_page_cache_init(void)
{
	u64 pa, size;
	int ret;
	int nid1, nid2;
	int i;

	BUILD_BUG_ON(MAX_SGX_NUMNODES > (SGX_EPC_NODE_MASK + 1));

	for_each_online_node(i) {
		pr_info("node %d: start=0x%llx end=0x%llx\n", i,
				PFN_PHYS(node_start_pfn(i)),
				PFN_PHYS(node_end_pfn(i)));
	}

	for (i = 0; i < SGX_MAX_EPC_BANKS; i++) {
		size = get_epc_bank_range(i, &pa);
		if (-1 == size)
			break;

		pr_info("EPC bank 0x%llx-0x%llx\n", pa, pa + size - 1);
		nid1 = address_to_node(pa);
		nid2 = address_to_node(pa + size - 1);

		if (nid1 == nid2 || -1 == nid1 || -1 == nid2) {
			if (-1 == nid1) {
				if (-1 == nid2)
					nid1 = 0;
				else
					nid1 = nid2;
			}
			ret = sgx_init_epc_bank(pa, size,
				sgx_nr_epc_banks++, nid1);
		} else {
			/* We have a bank that crosses boundaries */
			unsigned long boundary = PFN_PHYS(node_end_pfn(nid1));

			pr_info("\tEPC bank crosses boundary nodes %d and %d at address 0x%lx\n",
						nid1, nid2, boundary);
			ret = sgx_init_epc_bank(pa, boundary-pa,
				sgx_nr_epc_banks++, nid1);
			if (ret) {
				sgx_page_cache_teardown();
				return ret;
			}
			ret = sgx_init_epc_bank(boundary, size+pa-boundary,
					sgx_nr_epc_banks++, nid2);
		}

		if (ret) {
			sgx_page_cache_teardown();
			return ret;
		}
	}

	if (!sgx_nr_epc_banks) {
		pr_err("There are zero EPC banks.\n");
		return -ENODEV;
	}

	ret = sgx_nodes_init();
	if (ret) {
		sgx_page_cache_teardown();
		return ret;
	}

	return 0;
}

static int sgx_pm_notifier_cb(struct notifier_block *nb, unsigned long action,
			      void *data)
{
	if (action == PM_SUSPEND_PREPARE || action == PM_HIBERNATION_PREPARE)
		sgx_pm_cnt++;

	return NOTIFY_DONE;
}

static __init int sgx_init(void)
{
	unsigned long fc;
	int ret;

	if (!boot_cpu_has(X86_FEATURE_SGX)) {
		pr_info("X86_FEATURE_SGX feature is not available on cpu\n");
		return false;
	}

	if (!boot_cpu_has(X86_FEATURE_SGX1)) {
		pr_info("X86_FEATURE_SGX1 feature is not available on cpu\n");
		return false;
	}

	rdmsrl(MSR_IA32_FEATURE_CONTROL, fc);
	if (!(fc & FEATURE_CONTROL_LOCKED)) {
		pr_info("IA32_FEATURE_CONTROL MSR is not locked\n");
		return false;
	}

	if (!(fc & FEATURE_CONTROL_SGX_ENABLE)) {
		pr_info("disabled by the firmware\n");
		return false;
	}

	if (!(fc & FEATURE_CONTROL_SGX_LE_WR))
		pr_info("IA32_SGXLEPUBKEYHASHn MSRs are not writable\n");

	sgx_pm_notifier.notifier_call = sgx_pm_notifier_cb;
	ret = register_pm_notifier(&sgx_pm_notifier);
	if (ret)
		return ret;

	ret = sgx_page_cache_init();
	if (ret)
		goto out_pm;

	sgx_enabled = true;
	sgx_lc_enabled = !!(fc & FEATURE_CONTROL_SGX_LE_WR);
	return 0;
out_pm:
	unregister_pm_notifier(&sgx_pm_notifier);
	return ret;
}

arch_initcall(sgx_init);
