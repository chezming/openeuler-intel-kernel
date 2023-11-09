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
