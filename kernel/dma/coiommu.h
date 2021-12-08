/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __COIOMMU_H
#define __COIOMMU_H

struct coiommu_dtt {
	void *root;
	unsigned int level;
};

struct coiommu {
	const struct coiommu_dev_ops *dev_ops;
	void *dev;
	unsigned short *endpoints;
	int ep_count;
	struct coiommu_dtt dtt;
};

#define dtt_to_coiommu(v) container_of(v, struct coiommu, dtt)
#define COIOMMU_UPPER_LEVEL_STRIDE	9
#define COIOMMU_UPPER_LEVEL_MASK	(((u64)1 << COIOMMU_UPPER_LEVEL_STRIDE) - 1)
#define COIOMMU_PT_LEVEL_STRIDE		10
#define COIOMMU_PT_LEVEL_MASK		(((u64)1 << COIOMMU_PT_LEVEL_STRIDE) - 1)

#endif /* __COIOMMU_H */
