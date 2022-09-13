// SPDX-License-Identifier: GPL-2.0-only
/*
 * VDPA device simulator core.
 *
 * Copyright (c) 2020, Red Hat Inc. All rights reserved.
 *     Author: Jason Wang <jasowang@redhat.com>
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/dma-map-ops.h>
#include <linux/vringh.h>
#include <linux/vdpa.h>
#include <linux/vhost_iotlb.h>
#include <linux/iova.h>

#include "vdpa_sw.h"

#define DRV_VERSION  "0.1"
#define DRV_AUTHOR   "Jason Wang <jasowang@redhat.com>"
#define DRV_DESC     "vDPA Device Simulator core"
#define DRV_LICENSE  "GPL v2"

static int batch_mapping = 1;
module_param(batch_mapping, int, 0444);
MODULE_PARM_DESC(batch_mapping, "Batched mapping 1 -Enable; 0 - Disable");

static int max_iotlb_entries = 2048;
module_param(max_iotlb_entries, int, 0444);
MODULE_PARM_DESC(max_iotlb_entries,
		 "Maximum number of iotlb entries. 0 means unlimited. (default: 2048)");

#define VDPA_SW_QUEUE_ALIGN PAGE_SIZE
#define VDPA_SW_QUEUE_MAX 256
#define VDPA_SW_VENDOR_ID 0

static struct vdpa_sw_dev *vdpa_to_sw(struct vdpa_device *vdpa)
{
	return container_of(vdpa, struct vdpa_sw_dev, vdpa);
}

static struct vdpa_sw_dev *dev_to_sw(struct device *dev)
{
	struct vdpa_device *vdpa = dev_to_vdpa(dev);

	return vdpa_to_sw(vdpa);
}

static void vdpa_sw_vq_notify(struct vringh *vring)
{
	struct vdpa_sw_virtqueue *vq =
		container_of(vring, struct vdpa_sw_virtqueue, vring);

	if (unlikely(!vq->cb))
		return;

	vq->cb(vq->cb_private);
}

static void vdpa_sw_queue_ready(struct vdpa_sw_dev *sdev, unsigned int idx)
{
	struct vdpa_sw_virtqueue *vq = &sdev->vqs[idx];

	vringh_init_iotlb(&vq->vring, sdev->dev_attr.supported_features,
			  VDPA_SW_QUEUE_MAX, false,
			  (struct vring_desc *)(uintptr_t)vq->desc_addr,
			  (struct vring_avail *)
			  (uintptr_t)vq->driver_addr,
			  (struct vring_used *)
			  (uintptr_t)vq->device_addr);

	vq->vring.notify = vdpa_sw_vq_notify;
}

static void vdpa_sw_vq_reset(struct vdpa_sw_dev *sdev,
			     struct vdpa_sw_virtqueue *vq)
{
	vq->ready = false;
	vq->desc_addr = 0;
	vq->driver_addr = 0;
	vq->device_addr = 0;
	vq->cb = NULL;
	vq->cb_private = NULL;
	vringh_init_iotlb(&vq->vring, sdev->dev_attr.supported_features,
			  VDPA_SW_QUEUE_MAX, false, NULL, NULL, NULL);

	vq->vring.notify = NULL;
}

static void vdpa_sw_do_reset(struct vdpa_sw_dev *sdev)
{
	unsigned long flags;
	int i;

	for (i = 0; i < sdev->dev_attr.nvqs; i++)
		vdpa_sw_vq_reset(sdev, &sdev->vqs[i]);

	spin_lock_irqsave(&sdev->iommu_lock, flags);
	vhost_iotlb_reset(sdev->iommu);
	spin_unlock_irqrestore(&sdev->iommu_lock, flags);

	sdev->features = 0;
	sdev->status = 0;
	++sdev->generation;
}

static int dir_to_perm(enum dma_data_direction dir)
{
	int perm = -EFAULT;

	switch (dir) {
	case DMA_FROM_DEVICE:
		perm = VHOST_MAP_WO;
		break;
	case DMA_TO_DEVICE:
		perm = VHOST_MAP_RO;
		break;
	case DMA_BIDIRECTIONAL:
		perm = VHOST_MAP_RW;
		break;
	default:
		break;
	}

	return perm;
}

static dma_addr_t vdpa_sw_map_range(struct vdpa_sw_dev *sdev, phys_addr_t paddr,
				    size_t size, unsigned int perm)
{
	unsigned long flags;
	struct iova *iova;
	dma_addr_t dma_addr;
	int ret;

	/* We set the limit_pfn to the maximum (ULONG_MAX - 1) */
	iova = alloc_iova(&sdev->iova, size >> iova_shift(&sdev->iova),
			  ULONG_MAX - 1, true);
	if (!iova)
		return DMA_MAPPING_ERROR;

	dma_addr = iova_dma_addr(&sdev->iova, iova);

	spin_lock_irqsave(&sdev->iommu_lock, flags);
	ret = vhost_iotlb_add_range(sdev->iommu, (u64)dma_addr,
				    (u64)dma_addr + size - 1, (u64)paddr, perm);
	spin_unlock_irqrestore(&sdev->iommu_lock, flags);

	if (ret) {
		__free_iova(&sdev->iova, iova);
		return DMA_MAPPING_ERROR;
	}

	return dma_addr;
}

static void vdpa_sw_unmap_range(struct vdpa_sw_dev *sdev, dma_addr_t dma_addr,
				size_t size)
{
	unsigned long flags;
	spin_lock_irqsave(&sdev->iommu_lock, flags);
	vhost_iotlb_del_range(sdev->iommu, (u64)dma_addr,
			      (u64)dma_addr + size - 1);
	spin_unlock_irqrestore(&sdev->iommu_lock, flags);

	free_iova(&sdev->iova, iova_pfn(&sdev->iova, dma_addr));
}

static dma_addr_t vdpa_sw_map_page(struct device *dev, struct page *page,
				   unsigned long offset, size_t size,
				   enum dma_data_direction dir,
				   unsigned long attrs)
{
	struct vdpa_sw_dev *sdev = dev_to_sw(dev);
	phys_addr_t paddr = page_to_phys(page) + offset;
	int perm = dir_to_perm(dir);

	if (perm < 0)
		return DMA_MAPPING_ERROR;

	return vdpa_sw_map_range(sdev, paddr, size, perm);
}

static void vdpa_sw_unmap_page(struct device *dev, dma_addr_t dma_addr,
			       size_t size, enum dma_data_direction dir,
			       unsigned long attrs)
{
	struct vdpa_sw_dev *sdev = dev_to_sw(dev);

	vdpa_sw_unmap_range(sdev, dma_addr, size);
}

static void *vdpa_sw_alloc_coherent(struct device *dev, size_t size,
				    dma_addr_t *dma_addr, gfp_t flag,
				    unsigned long attrs)
{
	struct vdpa_sw_dev *sdev = dev_to_sw(dev);
	phys_addr_t paddr;
	void *addr;

	addr = kmalloc(size, flag);
	if (!addr) {
		*dma_addr = DMA_MAPPING_ERROR;
		return NULL;
	}

	paddr = virt_to_phys(addr);

	*dma_addr = vdpa_sw_map_range(sdev, paddr, size, VHOST_MAP_RW);
	if (*dma_addr == DMA_MAPPING_ERROR) {
		kfree(addr);
		return NULL;
	}

	return addr;
}

static void vdpa_sw_free_coherent(struct device *dev, size_t size,
				  void *vaddr, dma_addr_t dma_addr,
				  unsigned long attrs)
{
	struct vdpa_sw_dev *sdev = dev_to_sw(dev);

	vdpa_sw_unmap_range(sdev, dma_addr, size);

	kfree(vaddr);
}

static const struct dma_map_ops vdpa_sw_dma_ops = {
	.map_page = vdpa_sw_map_page,
	.unmap_page = vdpa_sw_unmap_page,
	.alloc = vdpa_sw_alloc_coherent,
	.free = vdpa_sw_free_coherent,
};

static const struct vdpa_config_ops vdpa_sw_config_ops;
static const struct vdpa_config_ops vdpa_sw_batch_config_ops;

struct vdpa_sw_dev *vdpa_sw_create(struct vdpa_sw_dev_attr *dev_attr)
{
	const struct vdpa_config_ops *ops;
	struct vdpa_sw_dev *sdev;
	struct device *dev;
	int i, ret = -ENOMEM;

	if (batch_mapping)
		ops = &vdpa_sw_batch_config_ops;
	else
		ops = &vdpa_sw_config_ops;

	sdev = vdpa_alloc_device(struct vdpa_sw_dev, vdpa, NULL, ops, 1, 1,
				    dev_attr->name, false);
	if (IS_ERR(sdev)) {
		ret = PTR_ERR(sdev);
		goto err_alloc;
	}

	sdev->dev_attr = *dev_attr;
	mutex_init(&sdev->mutex);
	spin_lock_init(&sdev->iommu_lock);

	dev = &sdev->vdpa.dev;
	dev->dma_mask = &dev->coherent_dma_mask;
	if (dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64)))
		goto err_iommu;
	set_dma_ops(dev, &vdpa_sw_dma_ops);
	sdev->vdpa.mdev = dev_attr->mgmt_dev;

	sdev->config = kzalloc(dev_attr->config_size, GFP_KERNEL);
	if (!sdev->config)
		goto err_iommu;

	sdev->vqs = kcalloc(dev_attr->nvqs, sizeof(struct vdpa_sw_virtqueue),
			       GFP_KERNEL);
	if (!sdev->vqs)
		goto err_iommu;

	sdev->iommu = vhost_iotlb_alloc(max_iotlb_entries, 0);
	if (!sdev->iommu)
		goto err_iommu;

	for (i = 0; i < dev_attr->nvqs; i++) {
		struct vdpa_sw_virtqueue *vq = &sdev->vqs[i];

		vq->sdev = sdev;
		INIT_WORK(&vq->work, dev_attr->work_fn);
		mutex_init(&vq->mutex);

		vringh_set_iotlb(&vq->vring, sdev->iommu, &sdev->iommu_lock);
	}

	ret = iova_cache_get();
	if (ret)
		goto err_iommu;

	/* For swplicity we use an IOVA allocator with byte granularity */
	init_iova_domain(&sdev->iova, 1, 0);

	sdev->vdpa.dma_dev = dev;

	return sdev;

err_iommu:
	put_device(dev);
err_alloc:
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(vdpa_sw_create);

static int vdpa_sw_set_vq_address(struct vdpa_device *vdpa, u16 idx,
				  u64 desc_area, u64 driver_area,
				  u64 device_area)
{
	struct vdpa_sw_dev *sdev = vdpa_to_sw(vdpa);
	struct vdpa_sw_virtqueue *vq = &sdev->vqs[idx];

	vq->desc_addr = desc_area;
	vq->driver_addr = driver_area;
	vq->device_addr = device_area;

	return 0;
}

static void vdpa_sw_set_vq_num(struct vdpa_device *vdpa, u16 idx, u32 num)
{
	struct vdpa_sw_dev *sdev = vdpa_to_sw(vdpa);
	struct vdpa_sw_virtqueue *vq = &sdev->vqs[idx];

	vq->num = num;
	vq->reqs = krealloc_array(vq->reqs, num, sizeof(*vq->reqs), GFP_KERNEL);
}

static void vdpa_sw_kick_vq(struct vdpa_device *vdpa, u16 idx)
{
	struct vdpa_sw_dev *sdev = vdpa_to_sw(vdpa);
	struct vdpa_sw_virtqueue *vq = &sdev->vqs[idx];

	if (likely(vq->ready))
		vdpa_sw_schedule_work(&vq->work);
}

static void vdpa_sw_set_vq_cb(struct vdpa_device *vdpa, u16 idx,
			      struct vdpa_callback *cb)
{
	struct vdpa_sw_dev *sdev = vdpa_to_sw(vdpa);
	struct vdpa_sw_virtqueue *vq = &sdev->vqs[idx];

	vq->cb = cb->callback;
	vq->cb_private = cb->private;
}

static void vdpa_sw_set_vq_ready(struct vdpa_device *vdpa, u16 idx, bool ready)
{
	struct vdpa_sw_dev *sdev = vdpa_to_sw(vdpa);
	struct vdpa_sw_virtqueue *vq = &sdev->vqs[idx];

	mutex_lock(&vq->mutex);
	vq->ready = ready;
	if (vq->ready)
		vdpa_sw_queue_ready(sdev, idx);
	mutex_unlock(&vq->mutex);
}

static bool vdpa_sw_get_vq_ready(struct vdpa_device *vdpa, u16 idx)
{
	struct vdpa_sw_dev *sdev = vdpa_to_sw(vdpa);
	struct vdpa_sw_virtqueue *vq = &sdev->vqs[idx];

	return vq->ready;
}

static int vdpa_sw_set_vq_state(struct vdpa_device *vdpa, u16 idx,
				const struct vdpa_vq_state *state)
{
	struct vdpa_sw_dev *sdev = vdpa_to_sw(vdpa);
	struct vdpa_sw_virtqueue *vq = &sdev->vqs[idx];
	struct vringh *vrh = &vq->vring;

	mutex_lock(&vq->mutex);
	vrh->last_avail_idx = state->split.avail_index;
	mutex_unlock(&vq->mutex);

	return 0;
}

static int vdpa_sw_get_vq_state(struct vdpa_device *vdpa, u16 idx,
				struct vdpa_vq_state *state)
{
	struct vdpa_sw_dev *sdev = vdpa_to_sw(vdpa);
	struct vdpa_sw_virtqueue *vq = &sdev->vqs[idx];
	struct vringh *vrh = &vq->vring;

	state->split.avail_index = vrh->last_avail_idx;
	return 0;
}

static u32 vdpa_sw_get_vq_align(struct vdpa_device *vdpa)
{
	return VDPA_SW_QUEUE_ALIGN;
}

static u64 vdpa_sw_get_driver_features(struct vdpa_device *vdpa)
{
	struct vdpa_sw_dev *sdev = vdpa_to_sw(vdpa);

	return sdev->dev_attr.supported_features;
}

static int vdpa_sw_set_driver_features(struct vdpa_device *vdpa, u64 features)
{
	struct vdpa_sw_dev *sdev = vdpa_to_sw(vdpa);

	/* DMA mapping must be done by driver */
	if (!(features & (1ULL << VIRTIO_F_ACCESS_PLATFORM)))
		return -EINVAL;

	sdev->features = features & sdev->dev_attr.supported_features;

	return 0;
}

static void vdpa_sw_set_config_cb(struct vdpa_device *vdpa,
				  struct vdpa_callback *cb)
{
	/* We don't support config interrupt */
}

static u16 vdpa_sw_get_vq_num_max(struct vdpa_device *vdpa)
{
	return VDPA_SW_QUEUE_MAX;
}

static u32 vdpa_sw_get_device_id(struct vdpa_device *vdpa)
{
	struct vdpa_sw_dev *sdev = vdpa_to_sw(vdpa);

	return sdev->dev_attr.id;
}

static u32 vdpa_sw_get_vendor_id(struct vdpa_device *vdpa)
{
	return VDPA_SW_VENDOR_ID;
}

static u8 vdpa_sw_get_status(struct vdpa_device *vdpa)
{
	struct vdpa_sw_dev *sdev = vdpa_to_sw(vdpa);
	u8 status;

	mutex_lock(&sdev->mutex);
	status = sdev->status;
	mutex_unlock(&sdev->mutex);

	return status;
}

static void vdpa_sw_set_status(struct vdpa_device *vdpa, u8 status)
{
	struct vdpa_sw_dev *sdev = vdpa_to_sw(vdpa);

	mutex_lock(&sdev->mutex);
	sdev->status = status;
	mutex_unlock(&sdev->mutex);
}

static int vdpa_sw_reset(struct vdpa_device *vdpa)
{
	struct vdpa_sw_dev *sdev = vdpa_to_sw(vdpa);

	mutex_lock(&sdev->mutex);
	sdev->status = 0;
	vdpa_sw_do_reset(sdev);
	mutex_unlock(&sdev->mutex);

	return 0;
}

static size_t vdpa_sw_get_config_size(struct vdpa_device *vdpa)
{
	struct vdpa_sw_dev *sdev = vdpa_to_sw(vdpa);

	return sdev->dev_attr.config_size;
}

static void vdpa_sw_get_config(struct vdpa_device *vdpa, unsigned int offset,
			     void *buf, unsigned int len)
{
	struct vdpa_sw_dev *sdev = vdpa_to_sw(vdpa);

	if (offset + len > sdev->dev_attr.config_size)
		return;

	if (sdev->dev_attr.get_config)
		sdev->dev_attr.get_config(sdev, sdev->config);

	memcpy(buf, sdev->config + offset, len);
}

static void vdpa_sw_set_config(struct vdpa_device *vdpa, unsigned int offset,
			     const void *buf, unsigned int len)
{
	struct vdpa_sw_dev *sdev = vdpa_to_sw(vdpa);

	if (offset + len > sdev->dev_attr.config_size)
		return;

	memcpy(sdev->config + offset, buf, len);

	if (sdev->dev_attr.set_config)
		sdev->dev_attr.set_config(sdev, sdev->config);
}

static u32 vdpa_sw_get_generation(struct vdpa_device *vdpa)
{
	struct vdpa_sw_dev *sdev = vdpa_to_sw(vdpa);

	return sdev->generation;
}

static struct vdpa_iova_range vdpa_sw_get_iova_range(struct vdpa_device *vdpa)
{
	struct vdpa_iova_range range = {
		.first = 0ULL,
		.last = ULLONG_MAX,
	};

	return range;
}

static int vdpa_sw_set_map(struct vdpa_device *vdpa, unsigned int asid,
			   struct vhost_iotlb *iotlb)
{
	struct vdpa_sw_dev *sdev = vdpa_to_sw(vdpa);
	struct vhost_iotlb_map *map;
	u64 start = 0ULL, last = 0ULL - 1;
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&sdev->iommu_lock, flags);
	vhost_iotlb_reset(sdev->iommu);

	for (map = vhost_iotlb_itree_first(iotlb, start, last); map;
	     map = vhost_iotlb_itree_next(map, start, last)) {
		ret = vhost_iotlb_add_range(sdev->iommu, map->start,
					    map->last, map->addr, map->perm);
		if (ret)
			goto err;
	}
	spin_unlock_irqrestore(&sdev->iommu_lock, flags);
	return 0;

err:
	vhost_iotlb_reset(sdev->iommu);
	spin_unlock_irqrestore(&sdev->iommu_lock, flags);
	return ret;
}

static int vdpa_sw_dma_map(struct vdpa_device *vdpa, unsigned int asid, u64 iova, u64 size,
			   u64 pa, u32 perm, void *opaque)
{
	struct vdpa_sw_dev *sdev = vdpa_to_sw(vdpa);
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&sdev->iommu_lock, flags);
	ret = vhost_iotlb_add_range_ctx(sdev->iommu, iova, iova + size - 1,
					pa, perm, opaque);
	spin_unlock_irqrestore(&sdev->iommu_lock, flags);

	return ret;
}

static int vdpa_sw_dma_unmap(struct vdpa_device *vdpa, unsigned int asid, u64 iova, u64 size)
{
	struct vdpa_sw_dev *sdev = vdpa_to_sw(vdpa);
	unsigned long flags;

	spin_lock_irqsave(&sdev->iommu_lock, flags);
	vhost_iotlb_del_range(sdev->iommu, iova, iova + size - 1);
	spin_unlock_irqrestore(&sdev->iommu_lock, flags);

	return 0;
}

static void vdpa_sw_free(struct vdpa_device *vdpa)
{
	struct vdpa_sw_dev *sdev = vdpa_to_sw(vdpa);
	int i;

	for (i = 0; i < sdev->dev_attr.nvqs; i++) {
		struct vdpa_sw_virtqueue *vq = &sdev->vqs[i];

		cancel_work_sync(&vq->work);
		vringh_kiov_cleanup(&vq->out_iov);
		vringh_kiov_cleanup(&vq->in_iov);
		kfree(vq->reqs);
	}

	put_iova_domain(&sdev->iova);
	iova_cache_put();
	if (sdev->iommu)
		vhost_iotlb_free(sdev->iommu);
	kfree(sdev->vqs);
	kfree(sdev->config);
}

static const struct vdpa_config_ops vdpa_sw_config_ops = {
	.set_vq_address         = vdpa_sw_set_vq_address,
	.set_vq_num             = vdpa_sw_set_vq_num,
	.kick_vq                = vdpa_sw_kick_vq,
	.set_vq_cb              = vdpa_sw_set_vq_cb,
	.set_vq_ready           = vdpa_sw_set_vq_ready,
	.get_vq_ready           = vdpa_sw_get_vq_ready,
	.set_vq_state           = vdpa_sw_set_vq_state,
	.get_vq_state           = vdpa_sw_get_vq_state,
	.get_vq_align           = vdpa_sw_get_vq_align,
	.get_driver_features           = vdpa_sw_get_driver_features,
	.set_driver_features           = vdpa_sw_set_driver_features,
	.set_config_cb          = vdpa_sw_set_config_cb,
	.get_vq_num_max         = vdpa_sw_get_vq_num_max,
	.get_device_id          = vdpa_sw_get_device_id,
	.get_vendor_id          = vdpa_sw_get_vendor_id,
	.get_status             = vdpa_sw_get_status,
	.set_status             = vdpa_sw_set_status,
	.reset			= vdpa_sw_reset,
	.get_config_size        = vdpa_sw_get_config_size,
	.get_config             = vdpa_sw_get_config,
	.set_config             = vdpa_sw_set_config,
	.get_generation         = vdpa_sw_get_generation,
	.get_iova_range         = vdpa_sw_get_iova_range,
	.dma_map                = vdpa_sw_dma_map,
	.dma_unmap              = vdpa_sw_dma_unmap,
	.free                   = vdpa_sw_free,
};

static const struct vdpa_config_ops vdpa_sw_batch_config_ops = {
	.set_vq_address         = vdpa_sw_set_vq_address,
	.set_vq_num             = vdpa_sw_set_vq_num,
	.kick_vq                = vdpa_sw_kick_vq,
	.set_vq_cb              = vdpa_sw_set_vq_cb,
	.set_vq_ready           = vdpa_sw_set_vq_ready,
	.get_vq_ready           = vdpa_sw_get_vq_ready,
	.set_vq_state           = vdpa_sw_set_vq_state,
	.get_vq_state           = vdpa_sw_get_vq_state,
	.get_vq_align           = vdpa_sw_get_vq_align,
	.get_driver_features           = vdpa_sw_get_driver_features,
	.set_driver_features           = vdpa_sw_set_driver_features,
	.set_config_cb          = vdpa_sw_set_config_cb,
	.get_vq_num_max         = vdpa_sw_get_vq_num_max,
	.get_device_id          = vdpa_sw_get_device_id,
	.get_vendor_id          = vdpa_sw_get_vendor_id,
	.get_status             = vdpa_sw_get_status,
	.set_status             = vdpa_sw_set_status,
	.reset			= vdpa_sw_reset,
	.get_config_size        = vdpa_sw_get_config_size,
	.get_config             = vdpa_sw_get_config,
	.set_config             = vdpa_sw_set_config,
	.get_generation         = vdpa_sw_get_generation,
	.get_iova_range         = vdpa_sw_get_iova_range,
	.set_map                = vdpa_sw_set_map,
	.free                   = vdpa_sw_free,
};

MODULE_VERSION(DRV_VERSION);
MODULE_LICENSE(DRV_LICENSE);
MODULE_AUTHOR(DRV_AUTHOR);
MODULE_DESCRIPTION(DRV_DESC);
