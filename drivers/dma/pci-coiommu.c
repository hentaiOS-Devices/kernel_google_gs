// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/sizes.h>
#include <linux/mutex.h>
#include <linux/coiommu_dev.h>

#define PCI_VENDOR_ID_COIOMMU	0x1234
#define PCI_DEVICE_ID_COIOMMU	0xabcd
#define COIOMMU_MMIO_BAR	0
#define COIOMMU_NOTIFY_BAR	2

#define COIOMMU_CMD_ACTIVATE	1
#define PIN_PAGES_IN_BATCH	(1UL << 63)

struct coiommu_mmio_info {
	u64 dtt_addr;
	u64 command;
	u64 dtt_level;
	u8 triggers[];
};

struct coiommu_notify_info {
	u64 data;
};

struct coiommu_dev {
	struct coiommu_mmio_info *mmio_info;
	struct coiommu_notify_info *notify_map;
};

static struct pci_device_id pci_coiommu_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_COIOMMU, PCI_DEVICE_ID_COIOMMU), },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, pci_coiommu_ids);

static void coiommu_execute_cmd(u64 cmdval, void *__iomem cmd)
{
	/* MMIO write is not a sync write. The backend can handle this
	 * MMIO write async so the frontend can be returned back before
	 * this request is really completed.
	 *
	 * To make sure the cmd is really completed by the backend, we
	 * can simply read the cmd MMIO again. Once the read is completed
	 * then the previous write has been also completed.
	 */
	writeq(cmdval, cmd);
	readq(cmd);
}

static void sync_notify(struct coiommu_dev *cidev, u64 data)
{
	unsigned long flags;
	struct coiommu_notify_info *info;
	u64 id;

	local_irq_save(flags);

	id = smp_processor_id();
	info = cidev->notify_map + id;

	writeq(data, (void *__iomem)info);

	writeb(1, (void *__iomem)(cidev->mmio_info->triggers + id));

	while (readq((void *__iomem)info))
		continue;

	local_irq_restore(flags);
}

static int coiommu_execute_req(struct coiommu_dev *dev, unsigned long pfn, unsigned short bdf)
{
	if (!dev)
		return -EINVAL;

	sync_notify(dev, (pfn << 16) | bdf);

	return 0;
}

static int coiommu_execute_reqs(struct coiommu_dev *dev, struct pin_pages_info *pin_info)
{
	if (!pin_info)
		return -EINVAL;

	if (!pin_info->nr_pages)
		return 0;

	sync_notify(dev, (__pa(pin_info)) | PIN_PAGES_IN_BATCH);
	return 0;
}

static const struct coiommu_dev_ops dev_ops = {
	.execute_request = coiommu_execute_req,
	.execute_requests = coiommu_execute_reqs,
};

static int pci_coiommu_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	struct coiommu_dev *cidev;
	int ret;

	ret = pci_enable_device(dev);
	if (ret)
		return ret;

	cidev = kzalloc(sizeof(struct coiommu_dev), GFP_KERNEL);
	if (!cidev)
		return -ENOMEM;

	/*
	 * MMIO bar which contains mmio infos and trigger register.
	 * Each CPU has one byte trigger register to notify backend about
	 * the action. So Bar length should be longer than the mmio info size
	 * plus the number of possible cpus.
	 */
	if (pci_resource_len(dev, COIOMMU_MMIO_BAR) <
		(sizeof(struct coiommu_mmio_info) + num_possible_cpus())) {
		dev_err(&dev->dev, "Invalid bar%d length 0x%llx\n",
				COIOMMU_MMIO_BAR,
				pci_resource_len(dev, COIOMMU_MMIO_BAR));
		ret = -ENXIO;
		goto free_dev;
	}

	cidev->mmio_info = pci_iomap(dev, COIOMMU_MMIO_BAR,
				     pci_resource_len(dev, COIOMMU_MMIO_BAR));
	if (!cidev->mmio_info) {
		ret = -ENXIO;
		goto free_dev;
	}

	/*
	 * Notification bar. Each CPU has a 8byte register to hold the
	 * GFP pin info. So Bar length should be longer than multiply the
	 * number of possible cpus with 8.
	 */
	if (pci_resource_len(dev, COIOMMU_NOTIFY_BAR) <
			num_possible_cpus() * 8) {
		dev_err(&dev->dev, "Invalid bar%d length 0x%llx\n",
				COIOMMU_NOTIFY_BAR,
				pci_resource_len(dev, COIOMMU_NOTIFY_BAR));
		ret = -ENXIO;
		goto free_mmio;
	}

	cidev->notify_map = pci_iomap(dev, COIOMMU_NOTIFY_BAR,
				pci_resource_len(dev, COIOMMU_NOTIFY_BAR));
	if (!cidev->notify_map) {
		ret = -ENXIO;
		goto free_mmio;
	}

	coiommu_execute_cmd(COIOMMU_CMD_ACTIVATE,
			(void *__iomem)&cidev->mmio_info->command);

	dev_set_drvdata(&dev->dev, cidev);

	return 0;
free_mmio:
	pci_iounmap(dev, cidev->mmio_info);
free_dev:
	kfree(cidev);
	return ret;
}

static void pci_coiommu_remove(struct pci_dev *dev)
{
	struct coiommu_dev *cidev = dev_get_drvdata(&dev->dev);

	if (!cidev)
		return;

	pci_iounmap(dev, cidev->mmio_info);
	pci_iounmap(dev, cidev->notify_map);
	kfree(cidev);
}

static struct pci_driver pci_coiommu_driver = {
	.name = "pci-coiommu",
	.id_table = pci_coiommu_ids,
	.probe = pci_coiommu_probe,
	.remove = pci_coiommu_remove,
};

static int __init pci_coiommu_init(void)
{
	return pci_register_driver(&pci_coiommu_driver);
}

static void __exit pci_coiommu_exit(void)
{
	pci_unregister_driver(&pci_coiommu_driver);
}

MODULE_LICENSE("GPL v2");

module_init(pci_coiommu_init);
module_exit(pci_coiommu_exit);
