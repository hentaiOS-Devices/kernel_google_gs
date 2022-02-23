// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright(c) 2021 Intel Corporation. All rights reserved.
//
// Authors: Amadeusz Slawinski <amadeuszx.slawinski@linux.intel.com>
//          Cezary Rojewski <cezary.rojewski@intel.com>
//

#include <sound/soc.h>
#include <uapi/sound/tlv.h>
#include "avs.h"
#include "kcontrol.h"
#include "messages.h"
#include "path.h"

#define DSP_VOLUME_MAX		S32_MAX /* 0db */
#define DSP_VOLUME_STEP_MAX	30

static u32 ctlvol_to_dspvol(u32 value)
{
	if (value > DSP_VOLUME_STEP_MAX)
		value = 0;
	return DSP_VOLUME_MAX >> (DSP_VOLUME_STEP_MAX - value);
}

static u32 dspvol_to_ctlvol(u32 volume)
{
	if (volume > DSP_VOLUME_MAX)
		return DSP_VOLUME_STEP_MAX;
	return volume ? __fls(volume) : 0;
}

static int avs_kcontrol_volume_info(struct snd_kcontrol *kcontrol,
				    struct snd_ctl_elem_info *uinfo)
{
	struct avs_kcontrol_data *kctrl_data = kcontrol->private_data;
	struct avs_kcontrol_volume_data *volume_data = kctrl_data->data;

	uinfo->type = SNDRV_CTL_ELEM_TYPE_INTEGER;
	uinfo->count = volume_data->channels;
	uinfo->value.integer.min = 0;
	uinfo->value.integer.max = DSP_VOLUME_STEP_MAX;

	return 0;
}

static int avs_kcontrol_volume_get(struct snd_kcontrol *kcontrol,
				   struct snd_ctl_elem_value *ucontrol)
{
	struct avs_kcontrol_data *kctrl_data = kcontrol->private_data;
	struct avs_kcontrol_volume_data *volume_data = kctrl_data->data;
	struct avs_path_module *active_module;
	struct avs_volume_cfg *dspvols = NULL;
	size_t num_dspvols;
	int ret, i = 0;

	/* prevent access to modules while path is being constructed */
	mutex_lock(&kctrl_data->adev->path_mutex);

	active_module = kctrl_data->active_module;
	if (active_module) {
		ret = avs_ipc_peakvol_get_volume(kctrl_data->adev,
						 active_module->module_id,
						 active_module->instance_id,
						 &dspvols, &num_dspvols);
		if (ret) {
			mutex_unlock(&kctrl_data->adev->path_mutex);
			return AVS_IPC_RET(ret);
		}

		for ( ; i < num_dspvols; i++)
			ucontrol->value.integer.value[i] =
				dspvol_to_ctlvol(dspvols[i].target_volume);
	}
	for ( ; i < volume_data->channels; i++)
		ucontrol->value.integer.value[i] = volume_data->volume[i];

	mutex_unlock(&kctrl_data->adev->path_mutex);

	kfree(dspvols);
	return 0;
}

static int avs_kcontrol_volume_put(struct snd_kcontrol *kcontrol,
				   struct snd_ctl_elem_value *ucontrol)
{
	struct avs_kcontrol_data *kctrl_data = kcontrol->private_data;
	struct avs_kcontrol_volume_data *volume_data = kctrl_data->data;
	struct avs_path_module *active_module;
	struct avs_volume_cfg dspvol = {0};
	long *ctlvol = ucontrol->value.integer.value;
	int channels_max;
	int i, ret = 0, changed = 0;

	/* prevent access to modules while path is being constructed */
	mutex_lock(&kctrl_data->adev->path_mutex);

	active_module = kctrl_data->active_module;
	if (active_module)
		channels_max = active_module->template->in_fmt->num_channels;
	else
		channels_max = volume_data->channels;

	for (i = 0; i < channels_max; i++)
		if (volume_data->volume[i] != ctlvol[i])
			changed = 1;

	if (!changed) {
		mutex_unlock(&kctrl_data->adev->path_mutex);
		return 0;
	}

	memcpy(volume_data->volume, ctlvol, sizeof(*ctlvol) * channels_max);

	for (i = 1; i < channels_max; i++)
		if (volume_data->volume[i] != volume_data->volume[0])
			break;

	if (i == channels_max) {
		dspvol.channel_id = AVS_ALL_CHANNELS_MASK;
		dspvol.target_volume = ctlvol_to_dspvol(volume_data->volume[0]);

		if (active_module)
			ret = avs_ipc_peakvol_set_volume(kctrl_data->adev,
							 active_module->module_id,
							 active_module->instance_id,
							 &dspvol);
	} else {
		for (i = 0; i < channels_max; i++) {
			dspvol.channel_id = i;
			dspvol.target_volume = ctlvol_to_dspvol(volume_data->volume[i]);

			if (active_module)
				ret = avs_ipc_peakvol_set_volume(kctrl_data->adev,
								 active_module->module_id,
								 active_module->instance_id,
								 &dspvol);
			if (ret)
				break;
			memset(&dspvol, 0, sizeof(dspvol));
		}
	}

	mutex_unlock(&kctrl_data->adev->path_mutex);

	return ret ? AVS_IPC_RET(ret) : 1;
}

static const SNDRV_CTL_TLVD_DECLARE_DB_SCALE(avs_kcontrol_volume_tlv, -9000, 300, 1);

static struct snd_kcontrol_new avs_kcontrol_volume_template = {
	.iface = SNDRV_CTL_ELEM_IFACE_MIXER,
	.access = SNDRV_CTL_ELEM_ACCESS_TLV_READ | SNDRV_CTL_ELEM_ACCESS_READWRITE,
	.info = avs_kcontrol_volume_info,
	.get = avs_kcontrol_volume_get,
	.put = avs_kcontrol_volume_put,
	.tlv.p = avs_kcontrol_volume_tlv,
};

static void avs_kcontrol_private_free(struct snd_kcontrol *kcontrol)
{
	kfree(kcontrol->private_data);
}

/*
 * avs_kcontrol_volume_register() - register volume kcontrol
 * @widget: Widget to which kcontrol belongs
 * @id: Which kcontrol it is
 * @count: If there is more than one
 * @max_channels: Maximum number of channels that will be in use
 */
struct snd_kcontrol *
avs_kcontrol_volume_register(struct avs_dev *adev,
			     struct snd_soc_dapm_widget *widget, int id,
			     int count, int max_channels)
{
	struct avs_kcontrol_volume_data *volume_data = NULL;
	struct avs_kcontrol_data *kctrl_data = NULL;
	struct snd_kcontrol_new kctrl_tmpl;
	struct snd_kcontrol *kctrl;
	int ret, i;

	memcpy(&kctrl_tmpl, &avs_kcontrol_volume_template, sizeof(kctrl_tmpl));

	kctrl_data = kzalloc(sizeof(*kctrl_data), GFP_KERNEL);
	if (!kctrl_data) {
		kctrl = ERR_PTR(-ENOMEM);
		goto err;
	}

	volume_data = kzalloc(sizeof(*volume_data), GFP_KERNEL);
	if (!volume_data) {
		kctrl = ERR_PTR(-ENOMEM);
		goto err;
	}

	kctrl_data->adev = adev;
	kctrl_data->data = volume_data;

	volume_data->channels = max_channels;
	/* Set default volume to maximum, so we don't get users asking, why there is no sound */
	for (i = 0; i < max_channels; i++)
		volume_data->volume[i] = dspvol_to_ctlvol(DSP_VOLUME_MAX);

	/*
	 * There can be one or more volume kontrols, if there is one we just name it
	 * "%s Volume", but if there is more, we need to number them properly.
	 */
	if (count == 1)
		kctrl_tmpl.name = kasprintf(GFP_KERNEL, "%s DSP Volume", widget->name);
	else
		kctrl_tmpl.name = kasprintf(GFP_KERNEL, "%s DSP Volume%d", widget->name, id);

	if (!kctrl_tmpl.name) {
		kctrl = ERR_PTR(-ENOMEM);
		goto err;
	}

	kctrl = snd_ctl_new1(&kctrl_tmpl, kctrl_data);
	kfree(kctrl_tmpl.name);
	if (!kctrl)
		goto err;

	ret = snd_ctl_add(widget->dapm->card->snd_card, kctrl);
	if (ret) {
		snd_ctl_free_one(kctrl);
		kctrl = ERR_PTR(ret);
		goto err;
	}

	kctrl->private_free = avs_kcontrol_private_free;
	return kctrl;

err:
	kfree(kctrl_data);
	kfree(volume_data);

	return kctrl;
}

/*
 * avs_kcontrol_volume_module_init_fill_cfg_data() - Fills up data for module init IPC
 * @module: module for which kcontrol is being used
 * @vols: will point to data, needs to be freed by caller
 * @vols_size: will return data size in bytes
 */
int avs_kcontrol_volume_module_init(struct avs_path_module *module,
				    struct avs_volume_cfg **vols,
				    size_t *vols_size)
{
	struct avs_kcontrol_data *kctrl_data = module->template->kctrl->private_data;
	struct avs_kcontrol_volume_data *volume_data = kctrl_data->data;
	struct avs_volume_cfg *cd;
	int channels_max = module->template->in_fmt->num_channels;
	int i;

	for (i = 1; i < channels_max; i++)
		if (volume_data->volume[i] != volume_data->volume[0])
			break;

	if (i == channels_max)
		*vols_size = sizeof(*cd);
	else
		*vols_size = sizeof(*cd) * channels_max;

	cd = kzalloc(*vols_size, GFP_KERNEL);
	if (!cd)
		return -ENOMEM;

	if (i == channels_max) {
		cd[0].channel_id = AVS_ALL_CHANNELS_MASK;
		cd[0].target_volume = ctlvol_to_dspvol(volume_data->volume[0]);
		cd[0].curve_type = AVS_AUDIO_CURVE_NONE;
		cd[0].curve_duration = 0;
	} else {
		for (i = 0; i < channels_max; i++) {
			cd[i].channel_id = i;
			cd[i].target_volume = ctlvol_to_dspvol(volume_data->volume[i]);
			cd[i].curve_type = AVS_AUDIO_CURVE_NONE;
			cd[i].curve_duration = 0;
		}
	}

	*vols = cd;
	kctrl_data->active_module = module;

	return 0;
}

/* avs_kcontrol_module_deinit() - Sets active module to null, should be
 * used before freeing pipelines, so we are in "working" state
 * @module: module for which kcontrol is being used
 */
int avs_kcontrol_module_deinit(struct avs_path_module *module)
{
	struct snd_kcontrol *kcontrol = module->template->kctrl;
	struct avs_kcontrol_data *kctrl_data;

	if (kcontrol) {
		kctrl_data = kcontrol->private_data;
		kctrl_data->active_module = NULL;
	}

	return 0;
}

#define TL_SIZE 2 * sizeof(u32)

static int avs_tlv_set_large_config(struct avs_dev *adev,
				    struct avs_path_module *module,
				    struct avs_kcontrol_tlv_data *kctrl_tlv_data)
{
	struct avs_tlv *tlv;
	int i;

	tlv = kctrl_tlv_data->tlv;

	for (i = 0; i < kctrl_tlv_data->count; i++) {
		int ret;

		ret = avs_ipc_set_large_config(adev, module->module_id, module->instance_id,
					       tlv->type, (u8*)tlv->value, tlv->length);
		if (ret)
			return AVS_IPC_RET(ret);

		tlv = (struct avs_tlv *)((u8*)tlv + TL_SIZE + tlv->length);
	}

	return 0;
}

int avs_tlv_control_set(struct snd_kcontrol *kcontrol, const unsigned int __user *data,
			       unsigned int size)
{
	struct avs_kcontrol_data *kctrl_data = kcontrol->private_data;
	struct avs_kcontrol_tlv_data *kctrl_tlv_data;
	struct avs_path_module *active_module;
	struct snd_ctl_tlv tlv;
	struct avs_tlv *atlv;
	size_t check_size;
	int ret = 0;
	bool cache;
	int i;

	/* check if TL part of TLV makes sense */
	if (size < sizeof(tlv))
		return -EINVAL;
	if (copy_from_user(&tlv, data, sizeof(tlv)))
		return -EFAULT;
	if (tlv.length != size - sizeof(tlv)) /* sanity check */
		return -EINVAL;

	/* check if V part of TLV makes sense */
	if (tlv.length <= sizeof(*kctrl_tlv_data))
		return -EINVAL;

	kctrl_tlv_data = kzalloc(tlv.length, GFP_KERNEL);
	if (!kctrl_tlv_data)
		return -ENOMEM;
	if (copy_from_user(kctrl_tlv_data, (u8*)data + sizeof(tlv), tlv.length)) {
		ret = -EFAULT;
		goto err;
	}

	/* validate data before cacheing/sending */
	atlv = kctrl_tlv_data->tlv;
	check_size = TL_SIZE; /* TL of kctrl_tlv_data */
	for (i = 0; i < kctrl_tlv_data->count; i++) {
		check_size += TL_SIZE + atlv->length; /* V[i] of kctrl_tlv_data */
		if (check_size > tlv.length) {
			ret = -EINVAL;
			goto err;
		}
		atlv = (struct avs_tlv *)((u8*)atlv + TL_SIZE + atlv->length);
	}

	cache = !!(kctrl_tlv_data->flags & AVS_KCTRL_TLV_FLAGS_CACHE);
	active_module = kctrl_data->active_module;

	/* if no module is active and we don't cache data, then there is no target to talk to... */
	if (!cache && !active_module) {
		ret = -EINVAL;
		goto err;
	}

	/* send data to active module */
	if (active_module) {
		ret = avs_tlv_set_large_config(kctrl_data->adev, active_module, kctrl_tlv_data);
		if (ret) {
			ret = -EINVAL;
			goto err;
		}
	}

	if (cache) {
		if (kctrl_data->data)
			kfree(kctrl_data->data);
		kctrl_data->data = kctrl_tlv_data;
	} else {
		kfree(kctrl_tlv_data);
	}

	return 0;
err:
	kfree(kctrl_tlv_data);
	return ret;
}

int avs_kcontrol_tlv_module_init(struct avs_path_module *module)
{
	struct avs_kcontrol_data *kctrl_data = NULL;
	int ret;

	if (!module || !module->template || !module->template->kctrl || !module->template->kctrl->private_data)
		return 0;

	// set active module
	kctrl_data = module->template->kctrl->private_data;
	kctrl_data->active_module = module;

	if (kctrl_data->data) {
		struct avs_kcontrol_tlv_data *kctrl_tlv_data = kctrl_data->data;

		ret = avs_tlv_set_large_config(kctrl_data->adev, module, kctrl_tlv_data);
		if (ret)
			return ret;
	}

	return 0;
}
