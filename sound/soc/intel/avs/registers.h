/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright(c) 2021 Intel Corporation. All rights reserved.
 *
 * Authors: Cezary Rojewski <cezary.rojewski@intel.com>
 *          Amadeusz Slawinski <amadeuszx.slawinski@linux.intel.com>
 */

#ifndef __SOUND_SOC_INTEL_AVS_REGS_H
#define __SOUND_SOC_INTEL_AVS_REGS_H

/* Intel HD Audio General DSP Registers */
#define AZX_ADSP_GEN_BASE		0x0
#define AZX_ADSP_REG_ADSPCS		(AZX_ADSP_GEN_BASE + 0x04)

#define AZX_ADSPCS_CRST_MASK(cm)	(cm)
#define AZX_ADSPCS_CSTALL_MASK(cm)	((cm) << 8)
#define AZX_ADSPCS_SPA_MASK(cm)		((cm) << 16)
#define AZX_ADSPCS_CPA_MASK(cm)		((cm) << 24)

#endif /* __SOUND_SOC_INTEL_AVS_REGS_H */
