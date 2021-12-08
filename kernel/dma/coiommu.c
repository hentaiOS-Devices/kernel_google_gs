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

static inline struct coiommu *get_coiommu(struct device *dev)
{
	return NULL;
}

static bool is_page_pinned(unsigned long pfn)
{
	return false;
}

static void unmark_pfn(unsigned long pfn, bool clear_accessed)
{
}

static void unmark_pfns(unsigned long pfn, unsigned long nr_pages,
			bool clear_accessed)
{
}

static int mark_pfn(unsigned long pfn)
{
	return -EINVAL;
}

static int mark_pfns(unsigned long pfn, unsigned long nr_pages,
		     struct pin_pages_info *pin_info)
{
	return -EINVAL;
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
	phys_addr_t phys_addr = dma_to_phys(dev, dma_addr);
	unsigned long pfn = phys_addr >> PAGE_SHIFT;
	unsigned long nr_pages = get_aligned_nrpages(phys_addr, size);

	unmark_pfns(pfn, nr_pages, false);
}

static void unmark_sg_pfns(struct scatterlist *sgl,
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
		unmark_pfns(pfn, nr_pages, clear_accessed);
	}
}

static int pin_page(struct coiommu *coiommu, unsigned long pfn,
		    unsigned short bdf)
{
	int ret;

	ret = coiommu->dev_ops->execute_request(coiommu->dev, pfn, bdf);
	if (ret)
		return ret;

	if (!is_page_pinned(pfn)) {
		pr_err("%s: coiommu pin pfn 0x%lx failed\n", __func__, pfn);
		return -EFAULT;
	}

	return 0;
}

static int pin_page_list(struct coiommu *coiommu, struct pin_pages_info *pin_info)
{
	int ret, count;

	ret = coiommu->dev_ops->execute_requests(coiommu->dev, pin_info);
	if (ret)
		return ret;

	for (count = 0; count < pin_info->nr_pages; count++) {
		if (!is_page_pinned(pin_info->pfn[count])) {
			pr_err("%s: coiommu pin pfn 0x%llx failed\n",
				__func__, pin_info->pfn[count]);
			return -EFAULT;
		}
	}

	return 0;
}

static int pin_and_mark_pfn(struct device *dev, unsigned long pfn)
{
	unsigned short bdf = get_pci_device_id(dev);
	struct coiommu *coiommu = get_coiommu(dev);
	int ret = 0;

	if (!coiommu)
		return -ENODEV;

	ret = mark_pfn(pfn);
	if (ret)
		return ret;

	ret = pin_page(coiommu, pfn, bdf);
	if (unlikely(ret))
		unmark_pfn(pfn, true);

	return ret;
}

static int pin_and_mark_pfns(struct device *dev, unsigned long start_pfn,
			     unsigned long nr_pages)
{
	unsigned short bdf = get_pci_device_id(dev);
	struct coiommu *coiommu = get_coiommu(dev);
	struct pin_pages_info *pin_info;
	int ret;

	if (nr_pages == 1)
		return pin_and_mark_pfn(dev, start_pfn);

	if (!coiommu)
		return -ENODEV;

	pin_info = kzalloc(sizeof(struct pin_pages_info) +
				nr_pages * sizeof(unsigned long),
				GFP_ATOMIC);
	if (!pin_info)
		return -ENOMEM;

	ret = mark_pfns(start_pfn, nr_pages, pin_info);
	if (ret)
		goto out;

	if (pin_info->nr_pages > 0) {
		pin_info->bdf = bdf;
		ret = pin_page_list(coiommu, pin_info);
		if (unlikely(ret))
			/*
			 * Note - In case pin failures, all pfns required for
			 * this dma mapping shall fail, which means none of
			 * them will participate in the dma operations.
			 * Hence their map count shall be decremented.
			 */
			unmark_pfns(start_pfn, nr_pages, true);
	}

out:
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
	struct coiommu *coiommu = get_coiommu(dev);
	struct scatterlist *sg;
	unsigned long nr_pages = 0;
	phys_addr_t phys_addr;
	unsigned long pfn;
	struct pin_pages_info *pin_info = NULL;
	int i, ret = 0;

	if (!coiommu)
		return -ENODEV;

	for_each_sg(sgl, sg, nents, i) {
		phys_addr = sg_phys(sg);
		nr_pages +=  get_aligned_nrpages(phys_addr, sg->length);
	}

	pin_info = kzalloc(sizeof(struct pin_pages_info) +
			   nr_pages * sizeof(unsigned long), GFP_ATOMIC);
	if (!pin_info)
		return -ENOMEM;

	for_each_sg(sgl, sg, nents, i) {
		phys_addr = sg_phys(sg);
		pfn = phys_addr >> PAGE_SHIFT;
		nr_pages = get_aligned_nrpages(phys_addr, sg->length);

		ret = mark_pfns(pfn, nr_pages, pin_info);
		if (ret) {
			unmark_sg_pfns(sgl, i, true);
			goto out;
		}
	}

	if (pin_info->nr_pages > 0) {
		pin_info->bdf = bdf;
		ret = pin_page_list(coiommu, pin_info);
		if (unlikely(ret))
			/*
			 * Note - In case pin failures, all pfns required for this
			 * dma mapping shall fail, which means none of them will
			 * participate in the dma operations. Hence their map count
			 * shall be decremented.
			 */
			unmark_sg_pfns(sgl, nents, true);
	}

out:
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

	unmark_sg_pfns(sgl, nents, false);
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

	coiommu_set_endpoints(global_coiommu, ep_count, endpoints);
}
