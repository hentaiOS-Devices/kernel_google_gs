/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __COIOMMU_H
#define __COIOMMU_H

struct coiommu {
	const struct coiommu_dev_ops *dev_ops;
};

#endif /* __COIOMMU_H */
