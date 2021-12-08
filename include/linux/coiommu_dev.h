/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_COIOMMU_DEV_H
#define __LINUX_COIOMMU_DEV_H

struct pin_pages_info {
	unsigned short	bdf;
	unsigned short	pad[3];
	unsigned long	nr_pages;
	uint64_t	pfn[];
};

struct coiommu_dev_ops {
	int (*execute_request)(unsigned long pfn, unsigned short bdf);
	int (*execute_requests)(struct pin_pages_info *pin_info);
};

#endif /* __LINUX_COIOMMU_DEV_H */
