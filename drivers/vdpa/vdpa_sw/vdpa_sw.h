/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2020, Red Hat Inc. All rights reserved.
 */

#ifndef _VDPA_SW_H
#define _VDPA_SW_H

#include <linux/bvec.h>
#include <linux/iova.h>
#include <linux/vringh.h>
#include <linux/vdpa.h>
#include <linux/virtio_byteorder.h>
#include <linux/vhost_iotlb.h>
#include <uapi/linux/virtio_config.h>

//TODO: remove
#include <uapi/linux/virtio_blk.h>

#define VDPA_SW_FEATURES	((1ULL << VIRTIO_F_ANY_LAYOUT) | \
				 (1ULL << VIRTIO_F_VERSION_1)  | \
				 (1ULL << VIRTIO_F_ACCESS_PLATFORM))

struct vdpa_sw_virtqueue {
	struct vdpa_sw_dev *sdev;
	struct vringh vring;
	struct work_struct work;
	struct vringh_kiov in_iov;
	struct vringh_kiov out_iov;
	unsigned short head;
	bool ready;
	u64 desc_addr;
	u64 device_addr;
	u64 driver_addr;
	u32 num;
	void *cb_private;
	irqreturn_t (*cb)(void *data);

	/* mutex to synchronize virtqueue states */
	struct mutex mutex;

	/* TODO: remove and put in the block device virtqueue */
	struct vdpa_sw_blk_req *reqs;
	struct bio_vec bio[UIO_MAXIOV];
	bool work_rescheduled;
	unsigned long work_endtime;
};

struct vdpa_sw_blk_req {
	struct llist_node list;
	struct kiocb iocb;
	struct iov_iter iter;
	struct virtio_blk_outhdr hdr;
	struct bio_vec bio_status[1];
	struct vdpa_sw_virtqueue *vq;
	size_t len;
	size_t to_push;
	size_t pushed;
	long ret;
	u32 type;
	u16 index;
};

struct vdpa_sw_dev_attr {
	struct vdpa_mgmt_dev *mgmt_dev;
	const char *name;
	u64 supported_features;
	size_t config_size;
	int nvqs;
	u32 id;

	work_func_t work_fn;
	void (*get_config)(struct vdpa_sw_dev *sdev, void *config);
	void (*set_config)(struct vdpa_sw_dev *sdev, const void *config);
};

/* State of each vdpa_sw_dev device */
struct vdpa_sw_dev {
	struct vdpa_device vdpa;
	struct vdpa_sw_virtqueue *vqs;
	struct vdpa_sw_dev_attr dev_attr;

	/* virtio config according to device type */
	void *config;
	struct vhost_iotlb *iommu;
	struct iova_domain iova;
	u32 status;
	u32 generation;
	u64 features;

	/* spinlock to synchronize iommu table */
	spinlock_t iommu_lock;

	/* mutex to synchronize device states */
	struct mutex mutex;

	/* TODO: remove and put in the block device */
	struct file *backend;
	loff_t capacity;
	struct work_struct completion_work;
	struct llist_head pending_reqs;
	struct work_struct polling_work;
	struct llist_head polling_reqs;
};

struct vdpa_sw_dev *vdpa_sw_create(struct vdpa_sw_dev_attr *attr);

//#define HACK_VDPA_SW_SCHEDULE_CPU 10
static inline bool vdpa_sw_schedule_work(struct work_struct *work)
{
#ifdef HACK_VDPA_SW_SCHEDULE_CPU
	return schedule_work_on(HACK_VDPA_SW_SCHEDULE_CPU, work);
#else
	return schedule_work(work);
#endif
}

/* TODO: cross-endian support */
static inline bool vdpa_sw_is_little_endian(struct vdpa_sw_dev *sdev)
{
	return virtio_legacy_is_little_endian() ||
		(sdev->features & (1ULL << VIRTIO_F_VERSION_1));
}

static inline u16 vdpa_sw16_to_cpu(struct vdpa_sw_dev *sdev, __virtio16 val)
{
	return __virtio16_to_cpu(vdpa_sw_is_little_endian(sdev), val);
}

static inline __virtio16 cpu_to_vdpa_sw16(struct vdpa_sw_dev *sdev, u16 val)
{
	return __cpu_to_virtio16(vdpa_sw_is_little_endian(sdev), val);
}

static inline u32 vdpa_sw32_to_cpu(struct vdpa_sw_dev *sdev, __virtio32 val)
{
	return __virtio32_to_cpu(vdpa_sw_is_little_endian(sdev), val);
}

static inline __virtio32 cpu_to_vdpa_sw32(struct vdpa_sw_dev *sdev, u32 val)
{
	return __cpu_to_virtio32(vdpa_sw_is_little_endian(sdev), val);
}

static inline u64 vdpa_sw64_to_cpu(struct vdpa_sw_dev *sdev, __virtio64 val)
{
	return __virtio64_to_cpu(vdpa_sw_is_little_endian(sdev), val);
}

static inline __virtio64 cpu_to_vdpa_sw64(struct vdpa_sw_dev *sdev, u64 val)
{
	return __cpu_to_virtio64(vdpa_sw_is_little_endian(sdev), val);
}

#endif
