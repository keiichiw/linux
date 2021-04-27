// SPDX-License-Identifier: GPL-2.0-only
/*
 * VDPA software device for virtio-blk.
 *
 * Copyright (c) 2021, Red Hat Inc. All rights reserved.
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/blkdev.h>
#include <linux/vringh.h>
#include <linux/vdpa.h>
#include <linux/file.h>
#include <uapi/linux/virtio_blk.h>

#include "vdpa_sw.h"

#define DRV_VERSION  "0.1"
#define DRV_AUTHOR   "Stefano Garzarella <sgarzare@redhat.com>"
#define DRV_DESC     "vDPA software device for virtio-blk"
#define DRV_LICENSE  "GPL v2"

#define VDPA_SW_BLK_FEATURES	(VDPA_SW_FEATURES | \
				 (1ULL << VIRTIO_BLK_F_SIZE_MAX) | \
				 (1ULL << VIRTIO_BLK_F_SEG_MAX)  | \
				 (1ULL << VIRTIO_BLK_F_BLK_SIZE) | \
				 (1ULL << VIRTIO_BLK_F_TOPOLOGY) | \
				 (1ULL << VIRTIO_BLK_F_MQ))

#define VDPA_SW_BLK_SIZE_MAX	0x1000
#define VDPA_SW_BLK_SEG_MAX	32
#define VDPA_SW_BLK_VQ_NUM	4

#define VDPA_SW_BLK_POLL_SUBMISSION
#define VDPA_SW_BLK_POLL_COMPLETION

static char vdpa_sw_blk_id[VIRTIO_BLK_ID_BYTES] = "vdpa_sw_blk";

static bool vdpa_sw_blk_check_range(struct vdpa_sw_dev *sdev,
				   u64 start_sector, size_t range_size)
{
	u64 range_sectors = range_size >> SECTOR_SHIFT;

	if (range_size > VDPA_SW_BLK_SIZE_MAX * VDPA_SW_BLK_SEG_MAX)
		return false;

	if (start_sector > sdev->capacity)
		return false;

	if (range_sectors > sdev->capacity - start_sector)
		return false;

	return true;
}

static int vdpa_sw_blk_req_prepare_status(struct vdpa_sw_blk_req *req)
{
	struct vdpa_sw_virtqueue *vq = req->vq;
	int ret;

	/* status already prepared */
	if (req->bio_status[0].bv_page)
		return 0;

	/* If some operations fail, we need to skip the remaining bytes
	 * to put the status in the last byte
	 */
	if (unlikely(req->to_push - req->pushed > 0)) {
		vringh_kiov_advance(&vq->in_iov, req->to_push - req->pushed);
		req->pushed = req->to_push;
	}

	/* get status address (last byte in in_iov) */
	ret = vringh_bvec_iotlb(&vq->vring, &vq->in_iov, req->bio_status,
				ARRAY_SIZE(req->bio_status), VHOST_MAP_WO, 1);
	if (unlikely(ret < 0)) {
		return ret;
	}

	return 0;
}

static int vdpa_sw_blk_req_set_status(struct vdpa_sw_blk_req *req, u8 status)
{
	struct bio_vec *bio = &req->bio_status[0];
	void *kaddr, *to;

	kaddr = kmap_atomic(bio->bv_page);
	to = kaddr + bio->bv_offset;
	WRITE_ONCE(*(u8 *)to, status);
	kunmap_atomic(kaddr);

	return 0;
}

static u8 vdpa_sw_blk_req_io_complete(struct vdpa_sw_blk_req *req,
				      ssize_t bytes)
{
	struct vdpa_sw_dev *sdev = req->vq->sdev;
	u8 status = VIRTIO_BLK_S_OK;

	if (unlikely(bytes != req->len)) {
		dev_err(&sdev->vdpa.dev, "bytes: 0x%zx to_push 0x%zx\n",
			bytes, req->to_push);
		status = VIRTIO_BLK_S_IOERR;
		goto out;
	}

out:
	return status;
}

static void vdpa_sw_blk_req_complete(struct vdpa_sw_blk_req *req, u8 status)
{
	struct vdpa_sw_virtqueue *vq = req->vq;

	//printk("%s - req: %p ret: %ld\n", __func__, req, ret);

	vdpa_sw_blk_req_set_status(req, status);

	/* Make sure data is wrote before advancing index */
	smp_wmb();

	vringh_complete_iotlb(&vq->vring, req->index, req->pushed);

	/* Make sure used is visible before rasing the interrupt. */
	smp_wmb();

	/* TODO: call at the end after all req */
	if (vringh_need_notify_iotlb(&vq->vring) > 0)
		vringh_notify(&vq->vring);
}

static void vdpa_sw_blk_req_complete_async(struct vdpa_sw_blk_req *req)
{
	struct vdpa_sw_virtqueue *vq = req->vq;
	u8 status;

	mutex_lock_nested(&vq->mutex, 1);

	status = vdpa_sw_blk_req_io_complete(req, req->ret);
	vdpa_sw_blk_req_complete(req, status);

	mutex_unlock(&vq->mutex);
}

#ifdef VDPA_SW_BLK_POLL_COMPLETION
static void vdpa_sw_blk_iocb_complete(struct kiocb *iocb, long ret)
{
	struct vdpa_sw_blk_req *req = container_of(iocb, struct vdpa_sw_blk_req,
						  iocb);

	smp_store_release(&req->ret, ret);
	vdpa_sw_blk_req_complete_async(req);
}
#else /* async */
static void vdpa_sw_blk_iocb_complete(struct kiocb *iocb, long ret)
{
	struct vdpa_sw_blk_req *req = container_of(iocb, struct vdpa_sw_blk_req,
						  iocb);
	struct vdpa_sw_dev *sdev = req->vq->sdev;

	req->ret = ret;
	if (llist_add(&req->list, &sdev->pending_reqs))
		vdpa_sw_schedule_work(&sdev->completion_work);

	//TODO: understand if we can handle the request here
}
#endif /* VDPA_SW_BLK_POLL_COMPLETION */

static ssize_t vdpa_sw_blk_handle_req_io(struct vdpa_sw_blk_req *req,
					 size_t len, struct vringh_kiov *kiov,
					 u32 perm, unsigned int iter_dir)
{
	struct vdpa_sw_virtqueue *vq = req->vq;
	struct vdpa_sw_dev *sdev = vq->sdev;
	loff_t offset;
	ssize_t bytes;
	u64 sector;
	int ret;

	sector = vdpa_sw64_to_cpu(sdev, req->hdr.sector);
	offset = sector << SECTOR_SHIFT;

	if (unlikely(!vdpa_sw_blk_check_range(sdev, sector, len))) {
		dev_err(&sdev->vdpa.dev,
			"accessing over the capacity - offset: 0x%llx len: 0x%zx\n",
			offset, len);
		return -1;
	}

	ret = vringh_bvec_iotlb(&vq->vring, kiov, vq->bio, ARRAY_SIZE(vq->bio),
				perm, len);
	if (unlikely(ret < 0)) {
		dev_err(&sdev->vdpa.dev,
			"vringh_bvec_iotlb() error: %d offset: 0x%llx len: 0x%zx\n",
			ret, offset, len);
		return ret;
	}

	if (iter_dir == READ)
		req->pushed += len;

	ret = vdpa_sw_blk_req_prepare_status(req);
	if (unlikely(ret)) {
		dev_err(&sdev->vdpa.dev,
			"vdpa_sw_blk_req_prepare_status() error: %d\n", ret);
		return ret;
	}

	iov_iter_bvec(&req->iter, iter_dir, vq->bio, ret, len);

	req->iocb.ki_pos = offset;
	req->iocb.ki_filp = sdev->backend;
	req->iocb.ki_complete = vdpa_sw_blk_iocb_complete;
#ifdef VDPA_SW_BLK_POLL_COMPLETION
	req->iocb.ki_flags = IOCB_DIRECT | IOCB_HIPRI | IOCB_ALLOC_CACHE;
	req->ret = -EIOCBQUEUED;
#else /* async */
	req->iocb.ki_flags = IOCB_DIRECT;
#endif
	req->len = len;

	if (iter_dir == READ)
		bytes = call_read_iter(sdev->backend, &req->iocb, &req->iter);
	else
		bytes = call_write_iter(sdev->backend, &req->iocb, &req->iter);

#ifdef VDPA_SW_BLK_POLL_COMPLETION
	if (bytes == -EIOCBQUEUED) {
		if (llist_add(&req->list, &sdev->polling_reqs))
			vdpa_sw_schedule_work(&sdev->polling_work);
	}
#endif
	return bytes;
}

/* Returns 'true' if the request is handled (with or without an I/O error)
 * and the status is correctly written in the last byte of the 'in iov',
 * 'false' otherwise.
 */
static int vdpa_sw_blk_handle_req(struct vdpa_sw_dev *sdev,
				   struct vdpa_sw_virtqueue *vq)
{
	struct vdpa_sw_blk_req *req;
	ssize_t bytes;
	size_t to_pull;
	u8 status = VIRTIO_BLK_S_OK;
	int ret;

	ret = vringh_getdesc_iotlb(&vq->vring, &vq->out_iov, &vq->in_iov,
				   &vq->head, GFP_ATOMIC);
	if (unlikely(ret != 1))
		return ret;

	if (unlikely(vq->out_iov.used < 1 || vq->in_iov.used < 1)) {
		dev_err(&sdev->vdpa.dev, "missing headers - out_iov: %u in_iov %u\n",
			vq->out_iov.used, vq->in_iov.used);
		return -1;
	}

	if (unlikely(vq->in_iov.iov[vq->in_iov.used - 1].iov_len < 1)) {
		dev_err(&sdev->vdpa.dev, "request in header too short\n");
		return -1;
	}

	req = &vq->reqs[vq->head];
	memset(req, 0, sizeof(*req));

	req->index = vq->head;
	req->vq = vq;

	/* The last byte is the status and we checked if the last iov has
	 * enough room for it.
	 */
	req->to_push = vringh_kiov_length(&vq->in_iov) - 1;

	to_pull = vringh_kiov_length(&vq->out_iov);

	bytes = vringh_iov_pull_iotlb(&vq->vring, &vq->out_iov, &req->hdr,
				      sizeof(req->hdr));
	if (unlikely(bytes != sizeof(req->hdr))) {
		dev_err(&sdev->vdpa.dev, "request out header too short\n");
		return -1;
	}

	to_pull -= bytes;

	req->type = vdpa_sw32_to_cpu(sdev, req->hdr.type);

	if (unlikely(!sdev->backend)) {
		status = VIRTIO_BLK_S_IOERR;
		goto out;
	}

	switch (req->type) {
	case VIRTIO_BLK_T_IN:
		bytes = vdpa_sw_blk_handle_req_io(req, req->to_push,
						  &vq->in_iov, VHOST_MAP_WO,
						  READ);
		if (bytes == -EIOCBQUEUED) {
			return 1;
		}

		status = vdpa_sw_blk_req_io_complete(req, bytes);
		break;

	case VIRTIO_BLK_T_OUT:
		bytes = vdpa_sw_blk_handle_req_io(req, to_pull, &vq->out_iov,
						  VHOST_MAP_RO, WRITE);

		if (bytes == -EIOCBQUEUED) {
			return 1;
		}

		status = vdpa_sw_blk_req_io_complete(req, bytes);
		break;

	case VIRTIO_BLK_T_GET_ID:
		bytes = vringh_iov_push_iotlb(&vq->vring, &vq->in_iov,
					      vdpa_sw_blk_id,
					      VIRTIO_BLK_ID_BYTES);
		if (bytes < 0) {
			dev_err(&sdev->vdpa.dev,
				"vringh_iov_push_iotlb() error: %zd\n", bytes);
			status = VIRTIO_BLK_S_IOERR;
			break;
		}

		req->pushed += bytes;
		break;

	default:
		dev_warn(&sdev->vdpa.dev,
			 "Unsupported request type %d\n", req->type);
		status = VIRTIO_BLK_S_IOERR;
		break;
	}

out:
	ret = vdpa_sw_blk_req_prepare_status(req);
	if (unlikely(ret)) {
		dev_err(&sdev->vdpa.dev,
			"vdpa_sw_blk_req_prepare_status() error: %d\n", ret);
		return ret;
	}

	local_bh_disable();
	vdpa_sw_blk_req_complete(req, status);
	local_bh_enable();

	return 1;
}

static inline unsigned long busy_clock(void)
{
	return local_clock() >> 10;
}

static void vdpa_sw_blk_vq_work(struct work_struct *work)
{
	struct vdpa_sw_virtqueue *vq =
		container_of(work, struct vdpa_sw_virtqueue, work);
	struct vdpa_sw_dev *sdev = vq->sdev;

	mutex_lock(&vq->mutex);

	if (unlikely(!(sdev->status & VIRTIO_CONFIG_S_DRIVER_OK)))
		goto out;

	if (unlikely(!vq->ready)) {
		goto out;
	}

#ifdef VDPA_SW_BLK_POLL_SUBMISSION
	if (!vq->work_rescheduled) {
		vringh_notify_disable_iotlb(&vq->vring);
		vq->work_endtime = busy_clock() + 200;
	}

	vq->work_rescheduled = false;
#else
	vringh_notify_disable_iotlb(&vq->vring);
#endif

	while (true) {
		int ret;

		ret = vdpa_sw_blk_handle_req(sdev, vq);
		if (unlikely(ret < 0)) {
			vringh_notify_enable_iotlb(&vq->vring);
			vringh_abandon_iotlb(&vq->vring, 1);
			break;
		} else if (unlikely(ret == 0)) {
#ifdef VDPA_SW_BLK_POLL_SUBMISSION
			/* Re-schedule to poll submission without re-enable
			 * notifications
			 */
			if (!time_after(busy_clock(), vq->work_endtime)) {
				vq->work_rescheduled = true;
				vdpa_sw_schedule_work(work);
				break;
			}
#endif
			if (!vringh_notify_enable_iotlb(&vq->vring)) {
				vringh_notify_disable_iotlb(&vq->vring);
				continue;
			}

			break;
		}

#ifdef VDPA_SW_BLK_POLL_SUBMISSION
		vq->work_endtime = busy_clock() + 200;
#endif
	}

out:
	mutex_unlock(&vq->mutex);
}

static void vdpa_sw_blk_completion_work(struct work_struct *work)
{
	struct vdpa_sw_dev *sdev = container_of(work, struct vdpa_sw_dev,
						completion_work);

	while (!llist_empty(&sdev->pending_reqs)) {
		struct vdpa_sw_blk_req *req, *tmp;
		struct llist_node *node;

		node = llist_del_all(&sdev->pending_reqs);
		llist_for_each_entry_safe(req, tmp, node, list) {
			vdpa_sw_blk_req_complete_async(req);
		}
	}
}

static void vdpa_sw_blk_polling_work(struct work_struct *work)
{
	struct vdpa_sw_dev *sdev = container_of(work, struct vdpa_sw_dev,
						polling_work);
	struct vdpa_sw_blk_req *req, *tmp;
	struct llist_node *node;

	/* or llist_del_first() and schedule */
	node = llist_del_all(&sdev->polling_reqs);
	llist_for_each_entry_safe(req, tmp, node, list) {
		if (smp_load_acquire(&req->ret) != -EIOCBQUEUED)
			continue;

		iocb_bio_iopoll(&req->iocb, NULL,
				BLK_POLL_NOSLEEP | BLK_POLL_ONESHOT);

		if (smp_load_acquire(&req->ret) == -EIOCBQUEUED) {
			if (llist_add(&req->list, &sdev->polling_reqs))
				vdpa_sw_schedule_work(work);
		}
	}
}

static void vdpa_sw_blk_get_config(struct vdpa_sw_dev *sdev, void *config)
{
	struct virtio_blk_config *blk_config = config;

	memset(config, 0, sizeof(struct virtio_blk_config));

	blk_config->capacity = cpu_to_vdpa_sw64(sdev, sdev->capacity);
	blk_config->size_max = cpu_to_vdpa_sw32(sdev, VDPA_SW_BLK_SIZE_MAX);
	blk_config->seg_max = cpu_to_vdpa_sw32(sdev, VDPA_SW_BLK_SEG_MAX);
	blk_config->num_queues = cpu_to_vdpa_sw16(sdev, VDPA_SW_BLK_VQ_NUM);
	blk_config->min_io_size = cpu_to_vdpa_sw16(sdev, 1);
	blk_config->opt_io_size = cpu_to_vdpa_sw32(sdev, 1);
	blk_config->blk_size = cpu_to_vdpa_sw32(sdev, SECTOR_SIZE);
}

static void vdpa_sw_blk_mgmtdev_release(struct device *dev)
{
}

static struct device vdpa_sw_blk_mgmtdev = {
	.init_name = "vdpasw_blk",
	.release = vdpa_sw_blk_mgmtdev_release,
};

static long vdpa_sw_blk_set_backend(struct vdpa_sw_dev *sdev, int fd)
{
	struct file *backend;
	loff_t capacity = 0;
	int ret;

	dev_info(&sdev->vdpa.dev, "set backend fd: %d sdev->backend: %p\n",
		 fd, sdev->backend);

	backend = fget(fd);
	if (IS_ERR(backend)) {
		ret = PTR_ERR(backend);
		goto out_dev;
	}

	if (backend) {
		loff_t cur;

		cur = vfs_llseek(backend, 0, SEEK_CUR);
		capacity = vfs_llseek(backend, 0, SEEK_END) >> SECTOR_SHIFT;
		vfs_llseek(backend, cur, SEEK_SET);
	}

	mutex_lock(&sdev->mutex);
	if (sdev->backend)
		fput(sdev->backend);

	sdev->backend = backend;
	sdev->capacity = capacity;
	mutex_unlock(&sdev->mutex);

	ret = 0;
out_dev:

	dev_info(&sdev->vdpa.dev, "set backend ret: %d sdev->backend: %p\n",
		 ret, sdev->backend);

	return ret;
}

static ssize_t backend_fd_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct vdpa_device *vdpa = container_of(dev, struct vdpa_device, dev);
	struct vdpa_sw_dev *sdev = container_of(vdpa, struct vdpa_sw_dev, vdpa);
	int ret;
	long fd;

	ret = kstrtol(buf, 0, &fd);
	if (ret)
		return ret;

	if (fd > INT_MAX || fd < INT_MIN)
		return -EINVAL;

	ret = vdpa_sw_blk_set_backend(sdev, fd);
	if (ret)
		return ret;

	/* Always return full write size even if we didn't consume all */
	return count;
}
DEVICE_ATTR_WO(backend_fd);

static const struct attribute_group vdpa_sw_blk_attr_group = {
	.attrs = (struct attribute *[]) {
		  &dev_attr_backend_fd.attr,
		  NULL
	}
};

static int vdpa_sw_blk_dev_add(struct vdpa_mgmt_dev *mdev, const char *name,
			       const struct vdpa_dev_set_config *config)
{
	struct vdpa_sw_dev_attr dev_attr = {};
	struct vdpa_sw_dev *sdev;
	int ret;

	dev_attr.mgmt_dev = mdev;
	dev_attr.name = name;
	dev_attr.id = VIRTIO_ID_BLOCK;
	dev_attr.supported_features = VDPA_SW_BLK_FEATURES;
	dev_attr.nvqs = VDPA_SW_BLK_VQ_NUM;
	dev_attr.config_size = sizeof(struct virtio_blk_config);
	dev_attr.get_config = vdpa_sw_blk_get_config;
	dev_attr.work_fn = vdpa_sw_blk_vq_work;

	sdev = vdpa_sw_create(&dev_attr);
	if (IS_ERR(sdev))
		return PTR_ERR(sdev);

	INIT_WORK(&sdev->completion_work, vdpa_sw_blk_completion_work);
	INIT_WORK(&sdev->polling_work, vdpa_sw_blk_polling_work);

	ret = _vdpa_register_device(&sdev->vdpa, VDPA_SW_BLK_VQ_NUM);
	if (ret)
		goto put_dev;

	ret = sysfs_create_group(&sdev->vdpa.dev.kobj, &vdpa_sw_blk_attr_group);
	if (ret < 0) {
		dev_err(&sdev->vdpa.dev, "failed to create sysfs attrs\n");
		goto put_dev;
	}

	return 0;

put_dev:
	put_device(&sdev->vdpa.dev);
	return ret;
}

static void vdpa_sw_blk_dev_del(struct vdpa_mgmt_dev *mdev,
				struct vdpa_device *dev)
{
	struct vdpa_sw_dev *sdev = container_of(dev, struct vdpa_sw_dev, vdpa);

	sysfs_remove_group(&sdev->vdpa.dev.kobj, &vdpa_sw_blk_attr_group);
	_vdpa_unregister_device(&sdev->vdpa);
}

static const struct vdpa_mgmtdev_ops vdpa_sw_blk_mgmtdev_ops = {
	.dev_add = vdpa_sw_blk_dev_add,
	.dev_del = vdpa_sw_blk_dev_del
};

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_BLOCK, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct vdpa_mgmt_dev mgmt_dev = {
	.device = &vdpa_sw_blk_mgmtdev,
	.id_table = id_table,
	.ops = &vdpa_sw_blk_mgmtdev_ops,
};

static int __init vdpa_sw_blk_init(void)
{
	int ret;

	ret = device_register(&vdpa_sw_blk_mgmtdev);
	if (ret)
		return ret;

	ret = vdpa_mgmtdev_register(&mgmt_dev);
	if (ret)
		goto parent_err;

	return 0;

parent_err:
	device_unregister(&vdpa_sw_blk_mgmtdev);
	return ret;
}

static void __exit vdpa_sw_blk_exit(void)
{
	vdpa_mgmtdev_unregister(&mgmt_dev);
	device_unregister(&vdpa_sw_blk_mgmtdev);
}

module_init(vdpa_sw_blk_init)
module_exit(vdpa_sw_blk_exit)

MODULE_VERSION(DRV_VERSION);
MODULE_LICENSE(DRV_LICENSE);
MODULE_AUTHOR(DRV_AUTHOR);
MODULE_DESCRIPTION(DRV_DESC);
