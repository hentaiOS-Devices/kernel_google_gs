// SPDX-License-Identifier: GPL-2.0
/*
 * Paravirtualized DMA operations that offers DMA inspection between
 * guest & host.
 */
#include <linux/mm.h>
#include <linux/dma-mapping.h>
#include <linux/dma-direct.h>
#include <linux/bitmap.h>
#include <linux/scatterlist.h>
#include <linux/pci.h>
#include <linux/dma-map-ops.h>
#include <linux/coiommu_dev.h>
#include "coiommu.h"
#include "direct.h"

static struct coiommu *global_coiommu;

static inline struct coiommu_dtt *get_coiommu_dtt(struct device *dev)
{
	return NULL;
}

static inline unsigned int dtt_level_to_offset(unsigned long pfn,
					       unsigned int level)
{
	unsigned int offset;

	if (level == DTT_LAST_LEVEL)
		return (pfn) & COIOMMU_PT_LEVEL_MASK;

	offset = COIOMMU_PT_LEVEL_STRIDE + (level - 2) * COIOMMU_UPPER_LEVEL_STRIDE;

	return (pfn >> offset) & COIOMMU_UPPER_LEVEL_MASK;
}

static void *dtt_alloc_page(void)
{
	return (void *)get_zeroed_page(GFP_ATOMIC | __GFP_ACCOUNT);
}

static struct dtt_leaf_entry *pfn_to_dtt_pte(struct coiommu_dtt *dtt,
					     unsigned long pfn, bool alloc)
{
	struct dtt_parent_entry *parent_pte;
	unsigned int index;
	struct dtt_leaf_entry *leaf_pte;
	unsigned int level = dtt->level;
	void *pt = (void *)dtt->root;
	u64 pteval;

	while (level != DTT_LAST_LEVEL) {
		index = dtt_level_to_offset(pfn, level);
		parent_pte = (struct dtt_parent_entry *)pt + index;

		if (!parent_pte_present(parent_pte)) {
			if (!alloc)
				break;
			pt = dtt_alloc_page();
			if (!pt)
				break;
			pteval = parent_pte_value(pt);
			if (cmpxchg64(&parent_pte->val, 0ULL, pteval))
				/* Someone else set it, free this one */
				free_page((unsigned long)pt);
		}

		pt = phys_to_virt(parent_pte_addr(parent_pte));
		level--;
	}

	if (level > DTT_LAST_LEVEL) {
		pr_err("coiommu: DTT %s failed at level %d for pfn 0x%lx\n",
			alloc ? "alloc" : "absent", level, pfn);
		return NULL;
	}

	index = dtt_level_to_offset(pfn, DTT_LAST_LEVEL);
	leaf_pte = (struct dtt_leaf_entry *)pt + index;

	return leaf_pte;
}

static bool is_page_pinned(struct coiommu_dtt *dtt, unsigned long pfn)
{
	struct dtt_leaf_entry *leaf_pte = pfn_to_dtt_pte(dtt, pfn, false);

	if (leaf_pte == NULL)
		return false;

	return coiommu_test_flag((1 << DTTE_PINNED_FLAG), &leaf_pte->dtte);
}

static void unmark_pfn(struct dtt_leaf_entry *leaf_pte, bool clear_accessed)
{
	if (!(atomic_read(&leaf_pte->dtte) & DTTE_MAP_CNT_MASK)) {
		pr_err("%s: coiomu: map count already zero, leaf_pte 0x%llx\n",
			__func__, (u64)leaf_pte);
		return;
	}

	if (!(atomic_dec_return(&leaf_pte->dtte) & DTTE_MAP_CNT_MASK)) {
		if (unlikely(clear_accessed))
			/*
			 * The clear_accessed is only true in the error handling code
			 * path, like pin a page failed and need reverse some operations.
			 * So this happens in rare.
			 * If this page is pinned successfully by another thread right
			 * before decreasing the map count here, then the access flag
			 * won't be cleared which is expected.
			 * If this page is pinned successfully by another thread right
			 * after decreasing the map count here, then the access flag
			 * will still be cleared. This won't cause any issue but just
			 * messes up access tracking a little bit.
			 */
			coiommu_clear_flag((1 << DTTE_ACCESSED_FLAG),
					&leaf_pte->dtte);
	}
}

static void unmark_pfns(struct coiommu_dtt *dtt, unsigned long pfn,
			unsigned long nr_pages, bool clear_accessed)
{
	struct dtt_leaf_entry *leaf_pte = NULL;
	unsigned long count = 0;
	unsigned int index = 0;

	for (; count < nr_pages; count++) {
		if (!leaf_pte || index > COIOMMU_PT_LEVEL_MASK) {
			leaf_pte = pfn_to_dtt_pte(dtt, pfn + count, false);
			if (leaf_pte == NULL) {
				pr_err("%s: coiommu: pfn 0x%lx pte is NULL\n",
					__func__, pfn + count);
				/* For the entries in the same page table
				 * page, they should all be NULL, so we
				 * can just skip all of them.
				 */
				index = dtt_level_to_offset(pfn + count,
							DTT_LAST_LEVEL);
				count += COIOMMU_PT_LEVEL_MASK - index;
				continue;
			}
			index = dtt_level_to_offset(pfn + count,
						DTT_LAST_LEVEL);
		} else
			leaf_pte += 1;

		unmark_pfn(leaf_pte, clear_accessed);
		index++;
	}
}

static int mark_pfn(struct coiommu_dtt *dtt,
		    struct dtt_leaf_entry *leaf_pte,
		    bool *pinned)
{
	unsigned long flags;
	unsigned int dtte;

	local_irq_save(flags);
	dtte = atomic_inc_return(&leaf_pte->dtte);
	if ((dtte & DTTE_MAP_CNT_MASK) > dtt->max_map_count) {
		pr_err("%s: coiommu: %d maps already done, leaf_pte 0x%llx\n",
			__func__, (dtte & DTTE_MAP_CNT_MASK), (u64)leaf_pte);
		atomic_dec(&leaf_pte->dtte);
		local_irq_restore(flags);
		return -EINVAL;
	}
	local_irq_restore(flags);

	coiommu_set_flag((1 << DTTE_ACCESSED_FLAG), &leaf_pte->dtte);

	if (pinned)
		*pinned = !!coiommu_test_flag((1 << DTTE_PINNED_FLAG),
					&leaf_pte->dtte);
	return 0;
}

static int mark_pfns(struct coiommu_dtt *dtt, unsigned long pfn,
		     unsigned long nr_pages, struct pin_pages_info *pin_info)
{
	struct dtt_leaf_entry *leaf_pte = NULL;
	unsigned long count = 0;
	unsigned int index = 0;
	bool pinned;
	int ret = 0;

	for (count = 0; count < nr_pages; count++) {
		if (!leaf_pte || index > COIOMMU_PT_LEVEL_MASK) {
			leaf_pte = pfn_to_dtt_pte(dtt, pfn + count, true);
			if (leaf_pte == NULL) {
				pr_err("%s: coiommu: pfn 0x%lx pte is NULL\n",
					__func__, pfn);
				ret = -EINVAL;
				goto out;
			}
			index = dtt_level_to_offset(pfn + count, DTT_LAST_LEVEL);
		} else
			leaf_pte += 1;

		ret = mark_pfn(dtt, leaf_pte, &pinned);
		if (ret)
			goto out;

		if (!pinned) {
			pin_info->pfn[pin_info->nr_pages] = pfn + count;
			pin_info->nr_pages++;
		}

		index++;
	}

	return 0;
out:
	unmark_pfns(dtt, pfn, count, true);
	return ret;
}

static inline unsigned long get_aligned_nrpages(phys_addr_t phys_addr,
						size_t size)
{
	return PAGE_ALIGN((phys_addr & (PAGE_SIZE - 1)) + size) >> PAGE_SHIFT;
}

static inline unsigned short get_pci_device_id(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);

	return PCI_DEVID(pdev->bus->number, pdev->devfn);
}

static void unmark_dma_addr(struct device *dev, size_t size,
			    dma_addr_t dma_addr)
{
	struct coiommu_dtt *dtt = get_coiommu_dtt(dev);
	phys_addr_t phys_addr = dma_to_phys(dev, dma_addr);
	unsigned long pfn = phys_addr >> PAGE_SHIFT;
	unsigned long nr_pages = get_aligned_nrpages(phys_addr, size);

	if (unlikely(!dtt))
		return;

	read_lock(&dtt->lock);
	if (likely(dtt->root))
		unmark_pfns(dtt, pfn, nr_pages, false);
	read_unlock(&dtt->lock);
}

static void unmark_sg_pfns(struct coiommu_dtt *dtt,
			   struct scatterlist *sgl,
			   int nents, bool clear_accessed)
{
	struct scatterlist *sg;
	phys_addr_t phys_addr;
	unsigned long pfn;
	unsigned long nr_pages;
	int i;

	for_each_sg(sgl, sg, nents, i) {
		phys_addr = sg_phys(sg);
		pfn = phys_addr >> PAGE_SHIFT;
		nr_pages = get_aligned_nrpages(phys_addr, sg->length);
		read_lock(&dtt->lock);
		if (unlikely(!dtt->root)) {
			read_unlock(&dtt->lock);
			return;
		}
		unmark_pfns(dtt, pfn, nr_pages, clear_accessed);
		read_unlock(&dtt->lock);
	}
}

static void unmark_sg(struct device *dev,
		      struct scatterlist *sgl,
		      int nents, bool clear_accessed)
{
	struct coiommu_dtt *dtt = get_coiommu_dtt(dev);

	if (likely(dtt))
		unmark_sg_pfns(dtt, sgl, nents, clear_accessed);
}

static int pin_page(struct coiommu_dtt *dtt, unsigned long pfn,
		    unsigned short bdf)
{
	struct coiommu *coiommu = dtt_to_coiommu(dtt);
	int ret;

	ret = coiommu->dev_ops->execute_request(coiommu->dev, pfn, bdf);
	if (ret)
		return ret;

	if (!is_page_pinned(dtt, pfn)) {
		pr_err("%s: coiommu pin pfn 0x%lx failed\n", __func__, pfn);
		return -EFAULT;
	}

	return 0;
}

static int pin_page_list(struct coiommu_dtt *dtt, struct pin_pages_info *pin_info)
{
	struct coiommu *coiommu = dtt_to_coiommu(dtt);
	int ret, count;

	ret = coiommu->dev_ops->execute_requests(coiommu->dev, pin_info);
	if (ret)
		return ret;

	for (count = 0; count < pin_info->nr_pages; count++) {
		if (!is_page_pinned(dtt, pin_info->pfn[count])) {
			pr_err("%s: coiommu pin pfn 0x%llx failed\n",
				__func__, pin_info->pfn[count]);
			return -EFAULT;
		}
	}

	return 0;
}

static int pin_and_mark_pfn(struct device *dev, unsigned long pfn)
{
	struct dtt_leaf_entry *leaf_pte;
	unsigned short bdf = get_pci_device_id(dev);
	struct coiommu_dtt *dtt = get_coiommu_dtt(dev);
	int ret = 0;
	bool pinned;

	if (!dtt)
		return -ENODEV;

	read_lock(&dtt->lock);

	if (unlikely(!dtt->root)) {
		ret = -ENODEV;
		goto out;
	}

	leaf_pte = pfn_to_dtt_pte(dtt, pfn, true);
	if (leaf_pte == NULL) {
		pr_err("%s: coiommu: pfn 0x%lx pte is NULL\n", __func__, pfn);
		ret = -EINVAL;
		goto out;
	}

	ret = mark_pfn(dtt, leaf_pte, &pinned);
	if (ret)
		goto out;

	if (!pinned) {
		ret = pin_page(dtt, pfn, bdf);
		if (unlikely(ret))
			unmark_pfn(leaf_pte, true);
	}

out:
	read_unlock(&dtt->lock);
	return ret;
}

static int pin_and_mark_pfns(struct device *dev, unsigned long start_pfn,
			     unsigned long nr_pages)
{
	unsigned short bdf = get_pci_device_id(dev);
	struct coiommu_dtt *dtt = get_coiommu_dtt(dev);
	struct pin_pages_info *pin_info;
	int ret;

	if (nr_pages == 1)
		return pin_and_mark_pfn(dev, start_pfn);

	if (!dtt)
		return -ENODEV;

	pin_info = kzalloc(sizeof(struct pin_pages_info) +
				nr_pages * sizeof(unsigned long),
				GFP_ATOMIC);
	if (!pin_info)
		return -ENOMEM;

	read_lock(&dtt->lock);

	if (unlikely(!dtt->root)) {
		ret = -ENODEV;
		goto out;
	}

	ret = mark_pfns(dtt, start_pfn, nr_pages, pin_info);
	if (ret)
		goto out;

	if (pin_info->nr_pages > 0) {
		pin_info->bdf = bdf;
		ret = pin_page_list(dtt, pin_info);
		if (unlikely(ret))
			/*
			 * Note - In case pin failures, all pfns required for
			 * this dma mapping shall fail, which means none of
			 * them will participate in the dma operations.
			 * Hence their map count shall be decremented.
			 */
			unmark_pfns(dtt, start_pfn, nr_pages, true);
	}

out:
	read_unlock(&dtt->lock);
	kfree(pin_info);
	return ret;
}

static int pin_and_mark_dma_addr(struct device *dev, size_t size,
				 dma_addr_t dma_addr)
{
	phys_addr_t phys_addr = dma_to_phys(dev, dma_addr);
	unsigned long nr_pages = get_aligned_nrpages(phys_addr, size);
	unsigned long pfn = phys_addr >> PAGE_SHIFT;
	int ret;

	ret = pin_and_mark_pfns(dev, pfn, nr_pages);
	if (unlikely(ret))
		dev_err(dev, "%s: coiommu failed to pin DMA buffer: %d\n",
			__func__, ret);

	return ret;
}

static int pin_and_mark_sg_list(struct device *dev,
				struct scatterlist *sgl,
				int nents)
{
	unsigned short bdf = get_pci_device_id(dev);
	struct coiommu_dtt *dtt = get_coiommu_dtt(dev);
	struct scatterlist *sg;
	unsigned long nr_pages = 0;
	phys_addr_t phys_addr;
	unsigned long pfn;
	struct pin_pages_info *pin_info = NULL;
	int i, ret = 0;

	if (!dtt)
		return -ENODEV;

	for_each_sg(sgl, sg, nents, i) {
		phys_addr = sg_phys(sg);
		nr_pages +=  get_aligned_nrpages(phys_addr, sg->length);
	}

	pin_info = kzalloc(sizeof(struct pin_pages_info) +
			   nr_pages * sizeof(unsigned long), GFP_ATOMIC);
	if (!pin_info)
		return -ENOMEM;

	read_lock(&dtt->lock);

	if (unlikely(!dtt->root)) {
		ret = -ENODEV;
		goto out;
	}

	for_each_sg(sgl, sg, nents, i) {
		phys_addr = sg_phys(sg);
		pfn = phys_addr >> PAGE_SHIFT;
		nr_pages = get_aligned_nrpages(phys_addr, sg->length);

		ret = mark_pfns(dtt, pfn, nr_pages, pin_info);
		if (ret) {
			unmark_sg_pfns(dtt, sgl, i, true);
			goto out;
		}
	}

	if (pin_info->nr_pages > 0) {
		pin_info->bdf = bdf;
		ret = pin_page_list(dtt, pin_info);
		if (unlikely(ret))
			/*
			 * Note - In case pin failures, all pfns required for this
			 * dma mapping shall fail, which means none of them will
			 * participate in the dma operations. Hence their map count
			 * shall be decremented.
			 */
			unmark_sg_pfns(dtt, sgl, nents, true);
	}

out:
	read_unlock(&dtt->lock);
	kfree(pin_info);
	return ret;
}

static void *coiommu_alloc(struct device *dev, size_t size,
			   dma_addr_t *dma_addr, gfp_t gfp,
			   unsigned long attrs)
{
	void *cpu_addr = dma_direct_alloc(dev, size, dma_addr, gfp, attrs);

	if (!cpu_addr) {
		dev_err(dev, "%s: failed\n", __func__);
		return NULL;
	}

	if (pin_and_mark_dma_addr(dev, size, *dma_addr))
		goto out_free;

	return cpu_addr;

out_free:
	dma_direct_free(dev, size, cpu_addr, *dma_addr, attrs);
	return NULL;
}

static void coiommu_free(struct device *dev, size_t size, void *cpu_addr,
			dma_addr_t dma_addr, unsigned long attrs)
{
	dma_direct_free(dev, size, cpu_addr, dma_addr, attrs);

	unmark_dma_addr(dev, size, dma_addr);
}

static struct page *coiommu_alloc_pages(struct device *dev, size_t size,
					dma_addr_t *dma_handle,
					enum dma_data_direction dir,
					gfp_t gfp)
{
	struct page *page = dma_direct_alloc_pages(dev, size, dma_handle,
						   dir, gfp);
	if (!page) {
		dev_err(dev, "%s: failed\n", __func__);
		return NULL;
	}

	if (pin_and_mark_dma_addr(dev, size, *dma_handle))
		goto out_free;

	return page;

out_free:
	dma_direct_free_pages(dev, size, page, *dma_handle, dir);
	return NULL;
}

static void coiommu_free_pages(struct device *dev, size_t size,
			       struct page *page, dma_addr_t dma_handle,
			       enum dma_data_direction dir)
{
	dma_direct_free_pages(dev, size, page, dma_handle, dir);

	unmark_dma_addr(dev, size, dma_handle);
}

static dma_addr_t coiommu_map_page(struct device *dev, struct page *page,
		unsigned long offset, size_t size, enum dma_data_direction dir,
		unsigned long attrs)
{
	dma_addr_t dma_addr = dma_direct_map_page(dev, page, offset,
						  size, dir, attrs);
	if (dma_addr == DMA_MAPPING_ERROR) {
		dev_err(dev, "%s: failed\n", __func__);
		return dma_addr;
	}

	if (pin_and_mark_dma_addr(dev, size, dma_addr))
		goto out_unmap;

	return dma_addr;

out_unmap:
	dma_direct_unmap_page(dev, dma_addr, size, dir,
			      attrs | DMA_ATTR_SKIP_CPU_SYNC);
	return DMA_MAPPING_ERROR;
}

static void coiommu_unmap_page(struct device *dev, dma_addr_t addr, size_t size,
			       enum dma_data_direction dir, unsigned long attrs)
{
	dma_direct_unmap_page(dev, addr, size, dir, attrs);

	unmark_dma_addr(dev, size, addr);
}

static int coiommu_map_sg(struct device *dev, struct scatterlist *sgl,
			 int nents, enum dma_data_direction dir,
			 unsigned long attrs)
{
	nents = dma_direct_map_sg(dev, sgl, nents, dir, attrs);
	if (!nents) {
		dev_err(dev, "%s: failed\n", __func__);
		return 0;
	}

	if (pin_and_mark_sg_list(dev, sgl, nents))
		goto out_unmap;

	return nents;

 out_unmap:
	dma_direct_unmap_sg(dev, sgl, nents, dir,
				attrs | DMA_ATTR_SKIP_CPU_SYNC);
	return 0;
}

static void coiommu_unmap_sg(struct device *dev, struct scatterlist *sgl,
			    int nents, enum dma_data_direction dir,
			    unsigned long attrs)
{
	dma_direct_unmap_sg(dev, sgl, nents, dir, attrs);

	unmark_sg(dev, sgl, nents, false);
}

static const struct dma_map_ops coiommu_ops = {
	.alloc			= coiommu_alloc,
	.free			= coiommu_free,
	.alloc_pages		= coiommu_alloc_pages,
	.free_pages		= coiommu_free_pages,
	.mmap			= dma_direct_mmap,
	.get_sgtable		= dma_direct_get_sgtable,
	.map_page		= coiommu_map_page,
	.unmap_page		= coiommu_unmap_page,
	.map_sg			= coiommu_map_sg,
	.unmap_sg		= coiommu_unmap_sg,
	.map_resource		= dma_direct_map_resource,
	.sync_single_for_cpu	= dma_direct_sync_single_for_cpu,
	.sync_single_for_device = dma_direct_sync_single_for_device,
	.sync_sg_for_cpu	= dma_direct_sync_sg_for_cpu,
	.sync_sg_for_device	= dma_direct_sync_sg_for_device,
	.dma_supported		= dma_direct_supported,
	.get_required_mask	= dma_direct_get_required_mask,
	.max_mapping_size	= dma_direct_max_mapping_size,
};

static inline unsigned int get_dtt_level(void)
{
	unsigned int pfn_width;

	pfn_width = MAX_PHYSMEM_BITS - PAGE_SHIFT;

	if (pfn_width <= COIOMMU_PT_LEVEL_STRIDE)
		return 1;

	return DIV_ROUND_UP((pfn_width - COIOMMU_PT_LEVEL_STRIDE),
			    COIOMMU_UPPER_LEVEL_STRIDE) + 1;
}

static void dtt_free(void *pt, unsigned int level)
{
	struct dtt_parent_entry *pte;
	u64 phys;
	int i;

	/*
	 * The last level contains the DMA tracking which doesn't
	 * point to any physical memory, so don't need to free any
	 * entry but the page itself.
	 */
	if (level == DTT_LAST_LEVEL)
		goto free;

	for (i = 0; i < 1 << COIOMMU_UPPER_LEVEL_STRIDE; i++) {
		pte = (struct dtt_parent_entry *)pt + i;
		if (!parent_pte_present(pte))
			continue;
		phys = parent_pte_addr(pte);
		dtt_free(phys_to_virt(phys), level - 1);
	}
free:

	free_page((unsigned long)pt);
}

static void dtt_root_free(struct coiommu_dtt *dtt)
{
	dtt_free((void *)dtt->root, dtt->level);
	dtt->root = NULL;
	dtt->level = 0;
}

int coiommu_enable_dtt(u64 *dtt_addr, u64 *dtt_level)
{
	struct coiommu_dtt *dtt;

	if (!global_coiommu) {
		pr_err("%s: coiommu not exists\n", __func__);
		return -EINVAL;
	}

	dtt = &global_coiommu->dtt;
	dtt->root = (void *)get_zeroed_page(GFP_KERNEL_ACCOUNT);
	if (!dtt->root)
		return -ENOMEM;
	dtt->level = get_dtt_level();

	if (dtt_addr)
		*dtt_addr = (u64)__pa(dtt->root);
	if (dtt_level)
		*dtt_level = (u64)dtt->level;
	/*
	 * It is possible that the same guest physical page will be mapped
	 * at the same time by different CPUs. So it is possible to increase
	 * the map_count at the same time by multiple CPU threads(see mark_pfn).
	 * To prevent map_count from exceeding the MAP_CNT_MASK, set the
	 * max map_count to be MAP_CNT_MASK - num_possible_cpus().
	 */
	dtt->max_map_count = DTTE_MAP_CNT_MASK - num_possible_cpus();
	pr_info("%s: coiommu max map_count: 0x%x\n",
		__func__, dtt->max_map_count);

	return 0;
}

void coiommu_disable_dtt(void)
{
	struct coiommu_dtt *dtt;
	unsigned long flags;

	if (!global_coiommu)
		return;

	dtt = &global_coiommu->dtt;
	if (!dtt->root)
		return;

	write_lock_irqsave(&dtt->lock, flags);
	dtt_root_free(dtt);
	write_unlock_irqrestore(&dtt->lock, flags);
}

static void coiommu_set_endpoints(struct coiommu *coiommu,
				  unsigned short ep_count,
				  unsigned short *endpoints)
{
	if (!endpoints)
		return;

	coiommu->endpoints = kcalloc(ep_count,
				sizeof(unsigned short), GFP_KERNEL);
	if (!coiommu->endpoints)
		return;

	memcpy(coiommu->endpoints, endpoints,
			ep_count * sizeof(unsigned short));
	coiommu->ep_count = ep_count;
}

void coiommu_init(unsigned short ep_count, unsigned short *endpoints)
{
	/*
	 * If already created means it is not the first time
	 * to init. Just re-use it.
	 */
	if (global_coiommu) {
		pr_warn("%s: coiommu is already initialized\n", __func__);
		return;
	}

	global_coiommu = kzalloc(sizeof(struct coiommu), GFP_KERNEL);
	if (!global_coiommu)
		return;

	rwlock_init(&global_coiommu->dtt.lock);
	coiommu_set_endpoints(global_coiommu, ep_count, endpoints);
}
