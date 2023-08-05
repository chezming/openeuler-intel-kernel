// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/pci.h>
#include <linux/vfio.h>

#include "vfio_pci_private.h"

void vfio_pci_probe_vf_bar_mmaps(struct vfio_pci_device *vdev)
{
	int i;

	if (!dev_is_pf(&vdev->pdev->dev))
		return;

	for (i = 0; i < PCI_SRIOV_NUM_BARS; i++) {
		int bar = i + PCI_IOV_RESOURCES;

		vfio_pci_probe_one_mmap(vdev, bar);
	}
}

static size_t vfio_pci_vf_bar_rw(struct vfio_pci_device *vdev, char __user *buf,
				 size_t count, loff_t *ppos, bool iswrite)
{
	return vfio_pci_bar_rw(vdev, buf, count, ppos, iswrite);
}

static void vfio_pci_vf_bar_release(struct vfio_pci_device *vdev,
				    struct vfio_pci_region *region)
{
	unsigned int index = (unsigned int)(unsigned long)region->data;

	vfio_pci_release_region(vdev, index);
}

static int vfio_pci_vf_bar_mmap(struct vfio_pci_device *vdev,
				struct vfio_pci_region *region,
				struct vm_area_struct *vma)
{
	unsigned int index = (unsigned int)(unsigned long)region->data;

	return vfio_pci_mmap_region(vdev, index, vma);
}

static const struct vfio_pci_regops vfio_pci_sriov_regops = {
	.rw		= vfio_pci_vf_bar_rw,
	.release	= vfio_pci_vf_bar_release,
	.mmap		= vfio_pci_vf_bar_mmap,
};

int vfio_pci_sriov_region_init(struct vfio_pci_device *vdev)
{
	struct pci_dev *pdev = vdev->pdev;
	unsigned int i;
	int ret;

	if (!dev_is_pf(&pdev->dev))
		return -ENODEV;

	for (i = 0; i < PCI_SRIOV_NUM_BARS; i++) {
		size_t size;
		u32 flags;

		size = pci_resource_len(pdev, i + PCI_IOV_RESOURCES);
		if (!size)
			flags = 0;
		else
			flags = VFIO_REGION_INFO_FLAG_READ |
				VFIO_REGION_INFO_FLAG_WRITE |
				VFIO_REGION_INFO_FLAG_MMAP;

		ret = vfio_pci_register_dev_region(vdev,
			VFIO_REGION_TYPE_SRIOV_VF_BAR, i,
			&vfio_pci_sriov_regops, size, flags,
			(void *)(unsigned long)(i + PCI_IOV_RESOURCES));
		if (ret)
			return ret;
	}

	return 0;
}
