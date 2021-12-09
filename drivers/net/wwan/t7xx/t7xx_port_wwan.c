// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021, MediaTek Inc.
 * Copyright (c) 2021, Intel Corporation.
 *
 * Authors:
 *  Amir Hanania <amir.hanania@intel.com>
 *  Chandrashekar Devegowda <chandrashekar.devegowda@intel.com>
 *  Haijun Liu <haijun.liu@mediatek.com>
 *  Moises Veleta <moises.veleta@intel.com>
 *  Ricardo Martinez<ricardo.martinez@linux.intel.com>
 *
 * Contributors:
 *  Andy Shevchenko <andriy.shevchenko@linux.intel.com>
 *  Chiranjeevi Rapolu <chiranjeevi.rapolu@intel.com>
 *  Eliot Lee <eliot.lee@intel.com>
 *  Sreehari Kancharla <sreehari.kancharla@intel.com>
 */

#include <linux/atomic.h>
#include <linux/bitfield.h>
#include <linux/dev_printk.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/minmax.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/wwan.h>

#include "t7xx_common.h"
#include "t7xx_port.h"
#include "t7xx_port_proxy.h"
#include "t7xx_state_monitor.h"

static int t7xx_port_ctrl_start(struct wwan_port *port)
{
	struct t7xx_port *port_mtk = wwan_port_get_drvdata(port);

	if (atomic_read(&port_mtk->usage_cnt))
		return -EBUSY;

	atomic_inc(&port_mtk->usage_cnt);
	return 0;
}

static void t7xx_port_ctrl_stop(struct wwan_port *port)
{
	struct t7xx_port *port_mtk = wwan_port_get_drvdata(port);

	atomic_dec(&port_mtk->usage_cnt);
}

static bool t7xx_port_wwan_multipkt_capable(struct t7xx_port_static *port)
{
	return port->tx_ch == PORT_CH_MBIM_TX ||
		(port->tx_ch >= PORT_CH_DSS0_TX && port->tx_ch <= PORT_CH_DSS7_TX);
}

static int t7xx_port_ctrl_tx(struct wwan_port *port, struct sk_buff *skb)
{
	struct t7xx_port *port_private = wwan_port_get_drvdata(port);
	size_t actual_count = 0, alloc_size = 0, txq_mtu = 0;
	struct t7xx_port_static *port_static;
	int i, multi_packet = 1, ret = 0;
	struct sk_buff *skb_ccci = NULL;
	struct t7xx_fsm_ctl *ctl;
	enum md_state md_state;
	unsigned int count;
	bool port_multi;

	count = skb->len;
	if (!count)
		return -EINVAL;

	port_static = port_private->port_static;
	ctl = port_private->t7xx_dev->md->fsm_ctl;
	md_state = t7xx_fsm_get_md_state(ctl);
	if (md_state == MD_STATE_WAITING_FOR_HS1 || md_state == MD_STATE_WAITING_FOR_HS2) {
		dev_warn(port_private->dev, "Cannot write to %s port when md_state=%d\n",
			 port_static->name, md_state);
		return -ENODEV;
	}

	txq_mtu = CLDMA_TXQ_MTU;

	if (port_private->flags & PORT_F_USER_HEADER) {
		if (port_private->flags & PORT_F_USER_HEADER && count > txq_mtu) {
			dev_err(port_private->dev, "Packet %u larger than MTU on %s port\n",
				count, port_static->name);
			return -ENOMEM;
		}

		alloc_size = min_t(size_t, txq_mtu, count);
		actual_count = alloc_size;
	} else {
		alloc_size = min_t(size_t, txq_mtu, count + CCCI_H_ELEN);
		actual_count = alloc_size - CCCI_H_ELEN;
		port_multi = t7xx_port_wwan_multipkt_capable(port_static);
		if ((count + CCCI_H_ELEN > txq_mtu) && port_multi)
			multi_packet = DIV_ROUND_UP(count, txq_mtu - CCCI_H_ELEN);
	}

	for (i = 0; i < multi_packet; i++) {
		struct ccci_header *ccci_h = NULL;

		if (multi_packet > 1 && multi_packet == i + 1) {
			actual_count = count % (txq_mtu - CCCI_H_ELEN);
			alloc_size = actual_count + CCCI_H_ELEN;
		}

		skb_ccci = __dev_alloc_skb(alloc_size, GFP_KERNEL);
		if (!skb_ccci)
			return -ENOMEM;

		ccci_h = skb_put(skb_ccci, CCCI_H_LEN);
		ccci_h->packet_header = 0;
		ccci_h->packet_len = cpu_to_le32(actual_count + CCCI_H_LEN);
		ccci_h->status &= cpu_to_le32(~HDR_FLD_CHN);
		ccci_h->status |= cpu_to_le32(FIELD_PREP(HDR_FLD_CHN, port_static->tx_ch));
		ccci_h->ex_msg = 0;

		memcpy(skb_put(skb_ccci, actual_count), skb->data + i * (txq_mtu - CCCI_H_ELEN),
		       actual_count);

		t7xx_port_proxy_set_seq_num(port_private, ccci_h);

		ret = t7xx_port_send_skb_to_md(port_private, skb_ccci, true);
		if (ret)
			goto err_free_skb;

		port_private->seq_nums[MTK_TX]++;

		if (multi_packet == 1)
			return actual_count;
		else if (multi_packet == i + 1)
			return count;
	}

err_free_skb:
	if (ret != -ENOMEM) {
		dev_err(port_private->dev, "Write error on %s port, %d\n", port_static->name, ret);
		dev_kfree_skb_any(skb_ccci);
	}

	return ret;
}

static const struct wwan_port_ops wwan_ops = {
	.start = t7xx_port_ctrl_start,
	.stop = t7xx_port_ctrl_stop,
	.tx = t7xx_port_ctrl_tx,
};

static int t7xx_port_wwan_init(struct t7xx_port *port)
{
	struct t7xx_port_static *port_static = port->port_static;

	port->rx_length_th = MAX_RX_QUEUE_LENGTH;
	port->flags |= PORT_F_RX_ADJUST_HEADER;

	if (port_static->rx_ch == PORT_CH_UART2_RX)
		port->flags |= PORT_F_RX_CH_TRAFFIC;

	return 0;
}

static void t7xx_port_wwan_uninit(struct t7xx_port *port)
{
	if (port->wwan_port) {
		if (port->chn_crt_stat) {
			spin_lock(&port->port_update_lock);
			port->chn_crt_stat = false;
			spin_unlock(&port->port_update_lock);
		}

		wwan_remove_port(port->wwan_port);
		port->wwan_port = NULL;
	}
}

static int t7xx_port_wwan_recv_skb(struct t7xx_port *port, struct sk_buff *skb)
{
	struct t7xx_port_static *port_static = port->port_static;

	if (port->flags & PORT_F_RX_CHAR_NODE) {
		if (!atomic_read(&port->usage_cnt)) {
			dev_err_ratelimited(port->dev, "Port %s is not opened, drop packets\n",
					    port_static->name);
			return -ENETDOWN;
		}
	}

	return t7xx_port_recv_skb(port, skb);
}

static int port_status_update(struct t7xx_port *port)
{
	struct t7xx_port_static *port_static = port->port_static;

	if (port_static->port_type != WWAN_PORT_UNKNOWN) {
		port->wwan_port = wwan_create_port(port->dev, port_static->port_type,
						   &wwan_ops, port);
		if (IS_ERR(port->wwan_port))
			return PTR_ERR(port->wwan_port);
	} else {
		port->wwan_port = NULL;
	}

	if (port->flags & PORT_F_RX_CHAR_NODE) {
		if (port->chan_enable) {
			port->flags &= ~PORT_F_RX_ALLOW_DROP;
		} else {
			port->flags |= PORT_F_RX_ALLOW_DROP;
			spin_lock(&port->port_update_lock);
			port->chn_crt_stat = false;
			spin_unlock(&port->port_update_lock);
		}
	}
	return 0;
}

static int t7xx_port_wwan_enable_chl(struct t7xx_port *port)
{
	spin_lock(&port->port_update_lock);
	port->chan_enable = true;
	spin_unlock(&port->port_update_lock);

	if (port->chn_crt_stat != port->chan_enable)
		port_status_update(port);

	return 0;
}

static int t7xx_port_wwan_disable_chl(struct t7xx_port *port)
{
	spin_lock(&port->port_update_lock);
	port->chan_enable = false;
	spin_unlock(&port->port_update_lock);

	if (port->chn_crt_stat != port->chan_enable)
		port_status_update(port);

	return 0;
}

static void t7xx_port_wwan_md_state_notify(struct t7xx_port *port, unsigned int state)
{
	if (state == MD_STATE_READY)
		port_status_update(port);
}

struct port_ops wwan_sub_port_ops = {
	.init = &t7xx_port_wwan_init,
	.recv_skb = &t7xx_port_wwan_recv_skb,
	.uninit = &t7xx_port_wwan_uninit,
	.enable_chl = &t7xx_port_wwan_enable_chl,
	.disable_chl = &t7xx_port_wwan_disable_chl,
	.md_state_notify = &t7xx_port_wwan_md_state_notify,
};
