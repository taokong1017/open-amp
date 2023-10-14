/*
 * Copyright (c) 2014, Mentor Graphics Corporation
 * Copyright (c) 2018, Xilinx Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <metal/io.h>
#include <metal/utilities.h>
#include <openamp/rsc_table_parser.h>

/* Resources handler */
static const rsc_handler rsc_handler_table[] = {
	handle_vdev_rsc, /**< virtio resource */
};

int handle_rsc_table(struct remoteproc *rproc,
		     struct resource_table *rsc_table, size_t size,
		     struct metal_io_region *io)
{
	struct fw_rsc_hdr *hdr;
	uint32_t rsc_type;
	unsigned int idx, offset;
	int status = 0;

	/* Validate rsc table header fields */

	/* Minimum rsc table size */
	if (sizeof(struct resource_table) > size) {
		return -RPROC_ERR_RSC_TAB_TRUNC;
	}

	/* Supported version */
	if (rsc_table->ver != RSC_TAB_SUPPORTED_VERSION) {
		return -RPROC_ERR_RSC_TAB_VER;
	}

	/* Offset array */
	offset = sizeof(struct resource_table)
		 + rsc_table->num * sizeof(rsc_table->offset[0]);

	if (offset > size) {
		return -RPROC_ERR_RSC_TAB_TRUNC;
	}

	/* Reserved fields - must be zero */
	if (rsc_table->reserved[0] != 0 || rsc_table->reserved[1] != 0) {
		return -RPROC_ERR_RSC_TAB_RSVD;
	}

	/* Loop through the offset array and parse each resource entry */
	for (idx = 0; idx < rsc_table->num; idx++) {
		hdr = (void *)((char *)rsc_table + rsc_table->offset[idx]);
		if (io && metal_io_virt_to_offset(io, hdr) == METAL_BAD_OFFSET)
			return -RPROC_ERR_RSC_TAB_TRUNC;
		rsc_type = hdr->type;
		if (rsc_type < RSC_LAST)
			status = rsc_handler_table[rsc_type](rproc, hdr);
		else if (rsc_type >= RSC_VENDOR_START &&
			 rsc_type <= RSC_VENDOR_END)
			status = handle_vendor_rsc(rproc, hdr);
		if (status == -RPROC_ERR_RSC_TAB_NS) {
			status = 0;
			continue;
		} else if (status) {
			break;
		}
	}

	return status;
}

int handle_vendor_rsc(struct remoteproc *rproc, void *rsc)
{
	if (rproc && rproc->ops->handle_rsc) {
		struct fw_rsc_vendor *vend_rsc = rsc;
		size_t len = vend_rsc->len;

		return rproc->ops->handle_rsc(rproc, rsc, len);
	}
	return -RPROC_ERR_RSC_TAB_NS;
}

int handle_vdev_rsc(struct remoteproc *rproc, void *rsc)
{
	struct fw_rsc_vdev *vdev_rsc = rsc;
	int i, num_vrings;
	unsigned int notifyid;
	struct fw_rsc_vdev_vring *vring_rsc;

	/* only assign notification IDs but do not initialize vdev */
	notifyid = vdev_rsc->notifyid;
	notifyid = remoteproc_allocate_id(rproc,
					  notifyid,
					  notifyid == RSC_NOTIFY_ID_ANY ?
					  RSC_NOTIFY_ID_ANY : notifyid + 1);
	if (notifyid != RSC_NOTIFY_ID_ANY)
		vdev_rsc->notifyid = notifyid;
	else
		return -RPROC_ERR_RSC_TAB_NP;

	num_vrings = vdev_rsc->num_of_vrings;
	for (i = 0; i < num_vrings; i++) {
		vring_rsc = &vdev_rsc->vring[i];
		notifyid = vring_rsc->notifyid;
		notifyid = remoteproc_allocate_id(rproc,
						  notifyid,
						  notifyid == RSC_NOTIFY_ID_ANY ?
						  RSC_NOTIFY_ID_ANY : notifyid + 1);
		if (notifyid != RSC_NOTIFY_ID_ANY)
			vring_rsc->notifyid = notifyid;
		else
			goto err;
	}

	return 0;

err:
	for (i--; i >= 0; i--) {
		vring_rsc = &vdev_rsc->vring[i];
		metal_bitmap_clear_bit(&rproc->bitmap, vring_rsc->notifyid);
	}
	metal_bitmap_clear_bit(&rproc->bitmap, vdev_rsc->notifyid);

	return -RPROC_ERR_RSC_TAB_NP;
}

size_t find_rsc(void *rsc_table, unsigned int rsc_type, unsigned int index)
{
	struct resource_table *r_table = rsc_table;
	struct fw_rsc_hdr *hdr;
	unsigned int i, rsc_index;
	unsigned int lrsc_type;

	metal_assert(r_table);
	if (!r_table)
		return 0;

	/* Loop through the offset array and parse each resource entry */
	rsc_index = 0;
	for (i = 0; i < r_table->num; i++) {
		hdr = (void *)((char *)r_table + r_table->offset[i]);
		lrsc_type = hdr->type;
		if (lrsc_type == rsc_type) {
			if (rsc_index++ == index)
				return r_table->offset[i];
		}
	}
	return 0;
}
