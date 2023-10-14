/*
 * Copyright (c) 2014, Mentor Graphics Corporation
 * All rights reserved.
 * Copyright (c) 2015 Xilinx, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <metal/alloc.h>
#include <metal/log.h>
#include <metal/utilities.h>
#include <openamp/remoteproc.h>
#include <openamp/remoteproc_virtio.h>
#include <openamp/rsc_table_parser.h>

/* try the internal list added by remoteproc_add_mem first and then get_mem callback */
static struct remoteproc_mem *
remoteproc_get_mem(struct remoteproc *rproc, const char *name,
		   metal_phys_addr_t pa, metal_phys_addr_t da,
		   void *va, size_t size, struct remoteproc_mem *buf)
{
	struct metal_list *node;
	struct remoteproc_mem *mem;

	/*
	 * Check name length to avoid overflow. This test has to be kept for
	 * MISRA compliance
	 */
	if (name && strlen(name) > RPROC_MAX_NAME_LEN)
		return NULL;

	metal_list_for_each(&rproc->mems, node) {
		mem = metal_container_of(node, struct remoteproc_mem, node);
		if (name) {
			if (!strncmp(name, mem->name, RPROC_MAX_NAME_LEN))
				return mem;
		} else if (pa != METAL_BAD_PHYS) {
			metal_phys_addr_t pa_start, pa_end;

			pa_start = mem->pa;
			pa_end = pa_start + mem->size;
			if (pa >= pa_start && (pa + size) <= pa_end && pa < pa_end)
				return mem;
		} else if (da != METAL_BAD_PHYS) {
			metal_phys_addr_t da_start, da_end;

			da_start = mem->da;
			da_end = da_start + mem->size;
			if (da >= da_start && (da + size) <= da_end && da < da_end)
				return mem;
		} else if (va) {
			if (metal_io_virt_to_offset(mem->io, va) !=
			    METAL_BAD_OFFSET)
				return mem;

		} else {
			return NULL;
		}
	}

	if (!rproc->ops->get_mem)
		return NULL;

	return rproc->ops->get_mem(rproc, name, pa, da, va, size, buf);
}

static metal_phys_addr_t
remoteproc_datopa(struct remoteproc_mem *mem, metal_phys_addr_t da)
{
	metal_phys_addr_t pa;

	pa = mem->pa + da - mem->da;
	return pa;
}

static metal_phys_addr_t
remoteproc_patoda(struct remoteproc_mem *mem, metal_phys_addr_t pa)
{
	metal_phys_addr_t da;

	da = mem->da + pa - mem->pa;
	return da;
}

static int remoteproc_parse_rsc_table(struct remoteproc *rproc,
				      struct resource_table *rsc_table,
				      size_t rsc_size)
{
	struct metal_io_region *io;

	if (!rsc_table)
		return -RPROC_EINVAL;

	io = remoteproc_get_io_with_va(rproc, rsc_table);
	return handle_rsc_table(rproc, rsc_table, rsc_size, io);
}

int remoteproc_set_rsc_table(struct remoteproc *rproc,
			     struct resource_table *rsc_table,
			     size_t rsc_size)
{
	int ret;
	struct metal_io_region *io;

	if (!rproc || !rsc_table || rsc_size == 0)
		return -RPROC_EINVAL;

	io = remoteproc_get_io_with_va(rproc, rsc_table);
	if (!io)
		return -RPROC_EINVAL;
	ret = remoteproc_parse_rsc_table(rproc, rsc_table, rsc_size);
	if (!ret) {
		rproc->rsc_table = rsc_table;
		rproc->rsc_len = rsc_size;
		rproc->rsc_io = io;
	}
	return ret;
}

struct remoteproc *remoteproc_init(struct remoteproc *rproc,
				   const struct remoteproc_ops *ops, void *priv)
{
	if (!rproc || !ops)
		return NULL;

	memset(rproc, 0, sizeof(*rproc));
	rproc->state = RPROC_OFFLINE;
	metal_mutex_init(&rproc->lock);
	metal_list_init(&rproc->mems);
	metal_list_init(&rproc->vdevs);
	rproc = ops->init(rproc, ops, priv);
	return rproc;
}

int remoteproc_remove(struct remoteproc *rproc)
{
	int ret = 0;

	if (!rproc)
		return -RPROC_EINVAL;

	metal_mutex_acquire(&rproc->lock);
	if (rproc->state == RPROC_OFFLINE) {
		if (rproc->ops->remove)
			rproc->ops->remove(rproc);
	} else {
		ret = -RPROC_EAGAIN;
	}
	metal_mutex_release(&rproc->lock);
	return ret;
}

int remoteproc_config(struct remoteproc *rproc, void *data)
{
	int ret = -RPROC_ENODEV;

	if (rproc) {
		metal_mutex_acquire(&rproc->lock);
		if (rproc->state == RPROC_OFFLINE) {
			/* configure operation is allowed if the state is
			 * offline or ready. This function can be called
			 * multiple times before start the remote.
			 */
			if (rproc->ops->config)
				ret = rproc->ops->config(rproc, data);
			else
				ret = 0;
			rproc->state = RPROC_READY;
		} else {
			ret = -RPROC_EINVAL;
		}
		metal_mutex_release(&rproc->lock);
	}
	return ret;
}

struct metal_io_region *
remoteproc_get_io_with_name(struct remoteproc *rproc,
			    const char *name)
{
	struct remoteproc_mem *mem;
	struct remoteproc_mem buf;

	if (!rproc)
		return NULL;

	mem = remoteproc_get_mem(rproc, name,
				 METAL_BAD_PHYS, METAL_BAD_PHYS, NULL, 0, &buf);
	if (mem)
		return mem->io;

	return NULL;
}

struct metal_io_region *
remoteproc_get_io_with_pa(struct remoteproc *rproc,
			  metal_phys_addr_t pa)
{
	struct remoteproc_mem *mem;
	struct remoteproc_mem buf;

	if (!rproc)
		return NULL;

	mem = remoteproc_get_mem(rproc, NULL, pa, METAL_BAD_PHYS, NULL, 0, &buf);
	if (mem)
		return mem->io;

	return NULL;
}

struct metal_io_region *
remoteproc_get_io_with_da(struct remoteproc *rproc,
			  metal_phys_addr_t da,
			  unsigned long *offset)
{
	struct remoteproc_mem *mem;
	struct remoteproc_mem buf;

	if (!rproc || !offset)
		return NULL;

	mem = remoteproc_get_mem(rproc, NULL, METAL_BAD_PHYS, da, NULL, 0, &buf);
	if (mem) {
		struct metal_io_region *io;
		metal_phys_addr_t pa;

		io = mem->io;
		pa = remoteproc_datopa(mem, da);
		*offset = metal_io_phys_to_offset(io, pa);
		return io;
	}

	return NULL;
}

struct metal_io_region *
remoteproc_get_io_with_va(struct remoteproc *rproc, void *va)
{
	struct remoteproc_mem *mem;
	struct remoteproc_mem buf;

	if (!rproc)
		return NULL;

	mem = remoteproc_get_mem(rproc, NULL, METAL_BAD_PHYS, METAL_BAD_PHYS,
				 va, 0, &buf);
	if (mem)
		return mem->io;

	return NULL;
}

void *remoteproc_mmap(struct remoteproc *rproc,
		      metal_phys_addr_t *pa, metal_phys_addr_t *da,
		      size_t size, unsigned int attribute,
		      struct metal_io_region **io)
{
	void *va = NULL;
	metal_phys_addr_t lpa, lda;
	struct remoteproc_mem *mem;
	struct remoteproc_mem buf;

	if (!rproc || size == 0 || (!pa && !da))
		return NULL;
	if (pa)
		lpa = *pa;
	else
		lpa = METAL_BAD_PHYS;
	if (da)
		lda =  *da;
	else
		lda = METAL_BAD_PHYS;
	mem = remoteproc_get_mem(rproc, NULL, lpa, lda, NULL, size, &buf);
	if (mem) {
		if (lpa != METAL_BAD_PHYS)
			lda = remoteproc_patoda(mem, lpa);
		else if (lda != METAL_BAD_PHYS)
			lpa = remoteproc_datopa(mem, lda);
		if (io)
			*io = mem->io;
		va = metal_io_phys_to_virt(mem->io, lpa);
	} else if (rproc->ops->mmap) {
		va = rproc->ops->mmap(rproc, &lpa, &lda, size, attribute, io);
	}

	if (pa)
		*pa  = lpa;
	if (da)
		*da = lda;
	return va;
}

unsigned int remoteproc_allocate_id(struct remoteproc *rproc,
				    unsigned int start,
				    unsigned int end)
{
	unsigned int notifyid = RSC_NOTIFY_ID_ANY;

	if (start == RSC_NOTIFY_ID_ANY)
		start = 0;
	if (end == RSC_NOTIFY_ID_ANY)
		end = METAL_BITS_PER_ULONG;
	if ((start < (8U * sizeof(rproc->bitmap))) &&
	    (end <= (8U * sizeof(rproc->bitmap)))) {
		notifyid = metal_bitmap_next_clear_bit(&rproc->bitmap,
						       start, end);
		if (notifyid != end)
			metal_bitmap_set_bit(&rproc->bitmap, notifyid);
		else
			notifyid = RSC_NOTIFY_ID_ANY;
	}
	return notifyid;
}

static int remoteproc_virtio_notify(void *priv, uint32_t id)
{
	struct remoteproc *rproc = priv;

	if (rproc->ops->notify)
		return rproc->ops->notify(rproc, id);

	return 0;
}

struct virtio_device *
remoteproc_create_virtio(struct remoteproc *rproc,
			 int vdev_id, unsigned int role,
			 void (*rst_cb)(struct virtio_device *vdev))
{
	char *rsc_table;
	struct fw_rsc_vdev *vdev_rsc;
	struct metal_io_region *vdev_rsc_io;
	struct virtio_device *vdev;
	struct remoteproc_virtio *rpvdev;
	size_t vdev_rsc_offset;
	unsigned int notifyid;
	unsigned int num_vrings, i;
	struct metal_list *node;

#ifdef VIRTIO_DRIVER_ONLY
	role = (role != VIRTIO_DEV_DRIVER) ? 0xFFFFFFFFUL : role;
#endif

#ifdef VIRTIO_DEVICE_ONLY
	role = (role != VIRTIO_DEV_DEVICE) ? 0xFFFFFFFFUL : role;
#endif

	if (!rproc || (role != VIRTIO_DEV_DEVICE && role != VIRTIO_DEV_DRIVER))
		return NULL;

	metal_assert(rproc);
	metal_mutex_acquire(&rproc->lock);
	rsc_table = rproc->rsc_table;
	vdev_rsc_io = rproc->rsc_io;
	vdev_rsc_offset = find_rsc(rsc_table, RSC_VDEV, vdev_id);
	if (!vdev_rsc_offset) {
		metal_mutex_release(&rproc->lock);
		return NULL;
	}
	vdev_rsc = (struct fw_rsc_vdev *)(rsc_table + vdev_rsc_offset);
	notifyid = vdev_rsc->notifyid;
	/* Check if the virtio device is already created */
	metal_list_for_each(&rproc->vdevs, node) {
		rpvdev = metal_container_of(node, struct remoteproc_virtio,
					    node);
		if (rpvdev->vdev.notifyid == notifyid) {
			metal_mutex_release(&rproc->lock);
			return &rpvdev->vdev;
		}
	}
	vdev = rproc_virtio_create_vdev(role, notifyid,
					vdev_rsc, vdev_rsc_io, rproc,
					remoteproc_virtio_notify,
					rst_cb);
	if (!vdev) {
		metal_mutex_release(&rproc->lock);
		return NULL;
	}

	rproc_virtio_wait_remote_ready(vdev);

	rpvdev = metal_container_of(vdev, struct remoteproc_virtio, vdev);
	metal_list_add_tail(&rproc->vdevs, &rpvdev->node);
	num_vrings = vdev_rsc->num_of_vrings;

	/* set the notification id for vrings */
	for (i = 0; i < num_vrings; i++) {
		struct fw_rsc_vdev_vring *vring_rsc;
		metal_phys_addr_t da;
		unsigned int num_descs, align;
		struct metal_io_region *io;
		void *va;
		size_t size;
		int ret;

		vring_rsc = &vdev_rsc->vring[i];
		notifyid = vring_rsc->notifyid;
		da = vring_rsc->da;
		num_descs = vring_rsc->num;
		align = vring_rsc->align;
		size = vring_size(num_descs, align);
		va = remoteproc_mmap(rproc, NULL, &da, size, 0, &io);
		if (!va)
			goto err1;
		ret = rproc_virtio_init_vring(vdev, i, notifyid,
					      va, io, num_descs, align);
		if (ret)
			goto err1;
	}
	metal_mutex_release(&rproc->lock);
	return vdev;

err1:
	remoteproc_remove_virtio(rproc, vdev);
	metal_mutex_release(&rproc->lock);
	return NULL;
}

void remoteproc_remove_virtio(struct remoteproc *rproc,
			      struct virtio_device *vdev)
{
	struct remoteproc_virtio *rpvdev;

	(void)rproc;
	metal_assert(vdev);

	if (vdev) {
		rpvdev = metal_container_of(vdev, struct remoteproc_virtio, vdev);
		metal_list_del(&rpvdev->node);
		rproc_virtio_remove_vdev(&rpvdev->vdev);
	}
}

int remoteproc_get_notification(struct remoteproc *rproc, uint32_t notifyid)
{
	struct remoteproc_virtio *rpvdev;
	struct metal_list *node;
	int ret;

	if (!rproc)
		return 0;

	metal_list_for_each(&rproc->vdevs, node) {
		rpvdev = metal_container_of(node, struct remoteproc_virtio,
					    node);
		ret = rproc_virtio_notified(&rpvdev->vdev, notifyid);
		if (ret)
			return ret;
	}

	return 0;
}
