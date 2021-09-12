// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright(c) 2021 Intel Corporation. All rights reserved.
//
// Authors: Cezary Rojewski <cezary.rojewski@intel.com>
//          Amadeusz Slawinski <amadeuszx.slawinski@linux.intel.com>
//

#include <sound/hdaudio_ext.h>
#include "avs.h"
#include "registers.h"

#define AVS_ADSPCS_INTERVAL_MS		500
#define AVS_ADSPCS_TIMEOUT_MS		50000

int avs_dsp_core_power(struct avs_dev *adev, u32 core_mask, bool active)
{
	u32 value, mask, reg;

	value = snd_hdac_adsp_readl(adev, AZX_ADSP_REG_ADSPCS);

	mask = AZX_ADSPCS_SPA_MASK(core_mask);
	value = active ? mask : 0;

	snd_hdac_adsp_updatel(adev, AZX_ADSP_REG_ADSPCS, mask, value);

	value = active ? AZX_ADSPCS_CPA_MASK(core_mask) : 0;

	return snd_hdac_adsp_readl_poll(adev, AZX_ADSP_REG_ADSPCS,
					reg, (reg & value) == value,
					AVS_ADSPCS_INTERVAL_MS,
					AVS_ADSPCS_TIMEOUT_MS);
}

int avs_dsp_core_reset(struct avs_dev *adev, u32 core_mask, bool reset)
{
	u32 value, mask, reg;

	value = snd_hdac_adsp_readl(adev, AZX_ADSP_REG_ADSPCS);

	mask = AZX_ADSPCS_CRST_MASK(core_mask);
	value = reset ? mask : 0;

	snd_hdac_adsp_updatel(adev, AZX_ADSP_REG_ADSPCS, mask, value);

	return snd_hdac_adsp_readl_poll(adev, AZX_ADSP_REG_ADSPCS,
					reg, (reg & value) == value,
					AVS_ADSPCS_INTERVAL_MS,
					AVS_ADSPCS_TIMEOUT_MS);
}

int avs_dsp_core_stall(struct avs_dev *adev, u32 core_mask, bool stall)
{
	u32 value, mask, reg;

	value = snd_hdac_adsp_readl(adev, AZX_ADSP_REG_ADSPCS);

	mask = AZX_ADSPCS_CSTALL_MASK(core_mask);
	value = stall ? mask : 0;

	snd_hdac_adsp_updatel(adev, AZX_ADSP_REG_ADSPCS, mask, value);

	return snd_hdac_adsp_readl_poll(adev, AZX_ADSP_REG_ADSPCS,
					reg, (reg & value) == value,
					AVS_ADSPCS_INTERVAL_MS,
					AVS_ADSPCS_TIMEOUT_MS);
}

int avs_dsp_core_enable(struct avs_dev *adev, u32 core_mask)
{
	int ret;

	ret = avs_dsp_op(adev, power, core_mask, true);
	if (ret)
		dev_warn(adev->dev, "core_mask %d power failed: %d\n",
			 core_mask, ret);

	ret = avs_dsp_op(adev, reset, core_mask, false);
	if (ret)
		dev_warn(adev->dev, "core_mask %d reset failed: %d\n",
			 core_mask, ret);

	return avs_dsp_op(adev, stall, core_mask, false);
}

int avs_dsp_core_disable(struct avs_dev *adev, u32 core_mask)
{
	int ret;

	ret = avs_dsp_op(adev, stall, core_mask, true);
	if (ret)
		dev_warn(adev->dev, "core_mask %d stall failed: %d\n",
			core_mask, ret);

	ret = avs_dsp_op(adev, reset, core_mask, true);
	if (ret)
		dev_warn(adev->dev, "core_mask %d reset failed: %d\n",
			core_mask, ret);

	return avs_dsp_op(adev, power, core_mask, false);
}
