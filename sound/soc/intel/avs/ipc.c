// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright(c) 2021 Intel Corporation. All rights reserved.
//
// Authors: Cezary Rojewski <cezary.rojewski@intel.com>
//          Amadeusz Slawinski <amadeuszx.slawinski@linux.intel.com>
//

#include <linux/slab.h>
#include <sound/hdaudio_ext.h>
#include "avs.h"
#include "messages.h"
#include "registers.h"

#define AVS_IPC_TIMEOUT_MS	300

static struct avs_notify_action *
notify_get_action(struct list_head *sub_list, u32 id, void *context)
{
	struct avs_notify_action *action;

	list_for_each_entry(action, sub_list, node) {
		if (context && action->context != context)
			continue;
		if (action->identifier == id)
			return action;
	}

	return NULL;
}

int avs_notify_subscribe(struct list_head *sub_list, u32 notify_id,
			 void (*callback)(union avs_notify_msg, void *, size_t, void *),
			 void *context)
{
	struct avs_notify_action *action;

	action = notify_get_action(sub_list, notify_id, context);
	if (action)
		return -EEXIST;

	action = kmalloc(sizeof(*action), GFP_KERNEL);
	if (!action)
		return -ENOMEM;

	action->identifier = notify_id;
	action->context = context;
	action->callback = callback;
	INIT_LIST_HEAD(&action->node);

	list_add_tail(&action->node, sub_list);
	return 0;
}

int avs_notify_unsubscribe(struct list_head *sub_list, u32 notify_id, void *context)
{
	struct avs_notify_action *action;

	action = notify_get_action(sub_list, notify_id, context);
	if (!action)
		return -ENOENT;

	list_del(&action->node);
	kfree(action);
	return 0;
}

static void avs_dsp_receive_rx(struct avs_dev *adev, u64 header)
{
	struct avs_ipc *ipc = adev->ipc;
	union avs_reply_msg msg = AVS_MSG(header);

	ipc->rx.header = header;
	if (!msg.status) {
		/* update size in case of LARGE_CONFIG_GET */
		if (msg.msg_target == AVS_MOD_MSG &&
		    msg.global_msg_type == AVS_MOD_LARGE_CONFIG_GET)
			ipc->rx.size = msg.ext.large_config.data_off_size;

		memcpy_fromio(ipc->rx.data, avs_uplink_addr(adev),
			      ipc->rx.size);
	}
}

static void avs_dsp_process_notification(struct avs_dev *adev, u64 header)
{
	struct avs_notify_action *action;
	union avs_notify_msg msg = AVS_MSG(header);
	size_t data_size = 0;
	void *data = NULL;

	switch (msg.notify_msg_type) {
		struct avs_notify_mod_data mod_data;

	case AVS_NOTIFY_FW_READY:
		dev_dbg(adev->dev, "FW READY %x\n", msg.primary);
		adev->ipc->ready = true;
		complete(&adev->fw_ready);
		break;

	case AVS_NOTIFY_PHRASE_DETECTED:
		data_size = sizeof(struct avs_notify_voice_data);
		break;

	case AVS_NOTIFY_RESOURCE_EVENT:
		data_size = sizeof(struct avs_notify_res_data);
		break;

	case AVS_NOTIFY_MODULE_EVENT:
		memcpy_fromio(&mod_data, avs_uplink_addr(adev), sizeof(mod_data));
		data_size = sizeof(mod_data) + mod_data.data_size;
		break;

	default:
		dev_warn(adev->dev, "unknown notification: 0x%x\n",
			 msg.primary);
		break;
	}

	if (data_size) {
		data = kmalloc(data_size, GFP_KERNEL);
		if (!data)
			return;

		memcpy_fromio(data, avs_uplink_addr(adev), data_size);
	}

	list_for_each_entry(action, &adev->notify_sub_list, node)
		if (action->identifier == msg.notify_msg_type)
			action->callback(msg, data, data_size, action->context);

	kfree(data);
}

void avs_dsp_process_response(struct avs_dev *adev, u64 header)
{
	struct avs_ipc *ipc = adev->ipc;
	unsigned long flags;

	if (avs_msg_is_reply(header)) {
		spin_lock_irqsave(&ipc->lock, flags);
		avs_dsp_receive_rx(adev, header);
		ipc->completed = true;
		spin_unlock_irqrestore(&ipc->lock, flags);
	} else {
		avs_dsp_process_notification(adev, header);
	}

	complete(&ipc->busy_completion);
}

irqreturn_t avs_ipc_irq_handler(struct avs_dev *adev)
{
	const struct avs_spec *const spec = adev->spec;
	struct avs_ipc *ipc = adev->ipc;
	u32 adspis, hipc_rsp, hipc_ack;
	irqreturn_t ret = IRQ_NONE;

	adspis = snd_hdac_adsp_readl(adev, AZX_ADSP_REG_ADSPIS);
	if (adspis == UINT_MAX || !(adspis & AZX_ADSP_ADSPIS_IPC))
		return ret;

	hipc_ack = snd_hdac_adsp_readl(adev, spec->hipc_ack);
	hipc_rsp = snd_hdac_adsp_readl(adev, spec->hipc_rsp);

	/* DSP acked host's request */
	if (hipc_ack & spec->hipc_ack_done) {
		/* mask done interrupt */
		snd_hdac_adsp_updatel(adev, spec->hipc_ctl,
				      AZX_ADSP_HIPCCTL_DONE, 0);

		complete(&ipc->done_completion);

		/* tell DSP it has our attention */
		snd_hdac_adsp_updatel(adev, spec->hipc_ack,
				      spec->hipc_ack_done,
				      spec->hipc_ack_done);
		/* unmask done interrupt */
		snd_hdac_adsp_updatel(adev, spec->hipc_ctl,
				      AZX_ADSP_HIPCCTL_DONE,
				      AZX_ADSP_HIPCCTL_DONE);
		ret = IRQ_HANDLED;
	}

	/* DSP sent new response to process */
	if (hipc_rsp & spec->hipc_rsp_busy) {
		/* mask busy interrupt */
		snd_hdac_adsp_updatel(adev, spec->hipc_ctl,
				      AZX_ADSP_HIPCCTL_BUSY, 0);

		ret = IRQ_WAKE_THREAD;
	}

	return ret;
}

irqreturn_t avs_dsp_irq_handler(int irq, void *dev_id)
{
	struct avs_dev *adev = dev_id;

	/* Check IPC interrupt status */
	return avs_dsp_op(adev, irq_handler);
}

irqreturn_t avs_dsp_irq_thread(int irq, void *dev_id)
{
	struct avs_dev *adev = dev_id;

	/* Dispatch IPC interrupt */
	return avs_dsp_op(adev, irq_thread);
}

static bool avs_ipc_is_busy(struct avs_ipc *ipc)
{
	struct avs_dev *adev = to_avs_dev(ipc->dev);
	const struct avs_spec *const spec = adev->spec;
	u32 hipc_rsp;

	hipc_rsp = snd_hdac_adsp_readl(adev, spec->hipc_rsp);
	return hipc_rsp & spec->hipc_rsp_busy;
}

static int avs_ipc_wait_busy_completion(struct avs_ipc *ipc, int timeout)
{
	int ret;

again:
	ret = wait_for_completion_timeout(&ipc->busy_completion,
					  msecs_to_jiffies(timeout));
	/*
	 * DSP could be unresponsive at this point e.g. manifested by
	 * EXCEPTION_CAUGHT notification. If so, no point in continuing.
	 */
	if (!ipc->ready)
		return -EPERM;

	if (!ret) {
		if (!avs_ipc_is_busy(ipc))
			return -ETIMEDOUT;
		/*
		 * Fw did its job, either notification or reply
		 * has been received - now wait until it's processed.
		 */
		wait_for_completion_killable(&ipc->busy_completion);
	}

	/* Ongoing notification bh may cause early wakeup */
	spin_lock_irq(&ipc->lock);
	if (!ipc->completed) {
		/* Reply delayed due to nofitication. */
		reinit_completion(&ipc->busy_completion);
		spin_unlock_irq(&ipc->lock);
		goto again;
	}

	spin_unlock_irq(&ipc->lock);
	return 0;
}

static void avs_ipc_msg_init(struct avs_ipc *ipc, struct avs_ipc_msg request,
			     struct avs_ipc_msg *reply)
{
	lockdep_assert_held(&ipc->lock);

	ipc->rx.header = 0;
	ipc->rx.size = reply ? reply->size : 0;
	ipc->completed = false;

	reinit_completion(&ipc->done_completion);
	reinit_completion(&ipc->busy_completion);
}

static void avs_dsp_send_tx(struct avs_dev *adev, const struct avs_ipc_msg *tx)
{
	const struct avs_spec *const spec = adev->spec;

	if (tx->size)
		memcpy_toio(avs_downlink_addr(adev), tx->data, tx->size);
	snd_hdac_adsp_writel(adev, spec->hipc_req_ext, tx->header >> 32);
	snd_hdac_adsp_writel(adev, spec->hipc_req,
			     (tx->header & UINT_MAX) | spec->hipc_req_busy);
}

static int avs_dsp_do_send_msg(struct avs_dev *adev, struct avs_ipc_msg request,
			       struct avs_ipc_msg *reply, int timeout)
{
	struct avs_ipc *ipc = adev->ipc;
	unsigned long flags;
	int ret;

	if (!ipc->ready)
		return -EPERM;

	mutex_lock(&ipc->mutex);

	spin_lock_irqsave(&ipc->lock, flags);
	avs_ipc_msg_init(ipc, request, reply);
	avs_dsp_send_tx(adev, &request);
	spin_unlock_irqrestore(&ipc->lock, flags);

	ret = avs_ipc_wait_busy_completion(ipc, timeout);
	if (ret) {
		if (ret == -ETIMEDOUT) {
			dev_crit(adev->dev, "communication severed: %d, rebooting dsp..\n",
				 ret);

			avs_ipc_block(ipc);
		}
		goto exit;
	}

	ret = ipc->rx.rsp.status;
	if (reply) {
		reply->header = ipc->rx.header;
		if (reply->data && ipc->rx.size)
			memcpy(reply->data, ipc->rx.data, reply->size);
	}

exit:
	mutex_unlock(&ipc->mutex);
	return ret;
}

static int avs_dsp_send_msg_sequence(struct avs_dev *adev,
				     struct avs_ipc_msg request,
				     struct avs_ipc_msg *reply, int timeout,
				     bool wake_d0i0, bool schedule_d0ix)
{
	return avs_dsp_do_send_msg(adev, request, reply, timeout);
}

int avs_dsp_send_pm_msg_timeout(struct avs_dev *adev,
				struct avs_ipc_msg request,
				struct avs_ipc_msg *reply, int timeout,
				bool wake_d0i0)
{
	return avs_dsp_send_msg_sequence(adev, request, reply, timeout,
					 wake_d0i0, false);
}

int avs_dsp_send_pm_msg(struct avs_dev *adev,
			struct avs_ipc_msg request,
			struct avs_ipc_msg *reply, bool wake_d0i0)
{
	return avs_dsp_send_pm_msg_timeout(adev, request, reply,
					   adev->ipc->default_timeout,
					   wake_d0i0);
}

int avs_dsp_send_msg_timeout(struct avs_dev *adev, struct avs_ipc_msg request,
			     struct avs_ipc_msg *reply, int timeout)
{
	return avs_dsp_send_msg_sequence(adev, request, reply, timeout,
					 false, false);
}

int avs_dsp_send_msg(struct avs_dev *adev, struct avs_ipc_msg request,
		     struct avs_ipc_msg *reply)
{
	return avs_dsp_send_msg_timeout(adev, request, reply,
					adev->ipc->default_timeout);
}

static int avs_dsp_do_send_rom_msg(struct avs_dev *adev, struct avs_ipc_msg request,
				   int timeout)
{
	struct avs_ipc *ipc = adev->ipc;
	unsigned long flags;
	int ret;

	mutex_lock(&ipc->mutex);

	spin_lock_irqsave(&ipc->lock, flags);
	avs_ipc_msg_init(ipc, request, NULL);
	avs_dsp_send_tx(adev, &request);
	spin_unlock_irqrestore(&ipc->lock, flags);

	/* ROM messages must be sent before master core is unstalled */
	avs_dsp_op(adev, stall, adev->spec->master_mask, false);

	ret = wait_for_completion_timeout(&ipc->done_completion,
					  msecs_to_jiffies(timeout));

	mutex_unlock(&ipc->mutex);

	if (!ret)
		return -ETIMEDOUT;
	return 0;
}

int avs_dsp_send_rom_msg_timeout(struct avs_dev *adev,
				 struct avs_ipc_msg request, int timeout)
{
	return avs_dsp_do_send_rom_msg(adev, request, timeout);
}

int avs_dsp_send_rom_msg(struct avs_dev *adev, struct avs_ipc_msg request)
{
	return avs_dsp_send_rom_msg_timeout(adev, request,
					    adev->ipc->default_timeout);
}

void avs_dsp_int_control(struct avs_dev *adev, bool enable)
{
	const struct avs_spec *const spec = adev->spec;
	u32 value;

	value = enable ? AZX_ADSP_ADSPIC_IPC : 0;
	snd_hdac_adsp_updatel(adev, AZX_ADSP_REG_ADSPIC,
			      AZX_ADSP_ADSPIC_IPC, value);

	value = enable ? AZX_ADSP_HIPCCTL_DONE : 0;
	snd_hdac_adsp_updatel(adev, spec->hipc_ctl,
			      AZX_ADSP_HIPCCTL_DONE, value);

	value = enable ? AZX_ADSP_HIPCCTL_BUSY : 0;
	snd_hdac_adsp_updatel(adev, spec->hipc_ctl,
			      AZX_ADSP_HIPCCTL_BUSY, value);
}

int avs_ipc_init(struct avs_ipc *ipc, struct device *dev)
{
	ipc->rx.data = devm_kzalloc(dev, AVS_MAILBOX_SIZE, GFP_KERNEL);
	if (!ipc->rx.data)
		return -ENOMEM;

	ipc->dev = dev;
	ipc->ready = false;
	ipc->default_timeout = AVS_IPC_TIMEOUT_MS;
	init_completion(&ipc->done_completion);
	init_completion(&ipc->busy_completion);
	spin_lock_init(&ipc->lock);
	mutex_init(&ipc->mutex);

	return 0;
}

void avs_ipc_block(struct avs_ipc *ipc)
{
	ipc->ready = false;
}
