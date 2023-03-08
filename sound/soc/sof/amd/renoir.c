// SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
//
// This file is provided under a dual BSD/GPLv2 license. When using or
// redistributing this file, you may do so under either license.
//
// Copyright(c) 2021 Advanced Micro Devices, Inc.
//
// Authors: Ajit Kumar Pandey <AjitKumar.Pandey@amd.com>

/*
 * Hardware interface for Audio DSP on Renoir platform
 */

#include <linux/platform_device.h>
#include <linux/module.h>
#include <sound/sof/xtensa.h>

#include "../ops.h"
#include "../sof-audio.h"
#include "acp.h"
#include "acp-dsp-offset.h"

#define I2S_BT_INSTANCE		0
#define I2S_SP_INSTANCE		1
#define PDM_DMIC_INSTANCE	2

#define I2S_MODE		0x04

static int renoir_dai_probe(struct snd_soc_dai *dai)
{
	struct snd_sof_dev *sdev = snd_soc_component_get_drvdata(dai->component);
	unsigned int val;

	/* Set pin config to I2S_MODE */
	snd_sof_dsp_write(sdev, ACP_DSP_BAR, ACP_I2S_PIN_CONFIG, I2S_MODE);

	val = snd_sof_dsp_read(sdev, ACP_DSP_BAR, ACP_I2S_PIN_CONFIG);
	if (val != I2S_MODE) {
		dev_err(sdev->dev, "I2S Mode is not supported (I2S_PIN_CONFIG: %#x)\n", val);
		return -EINVAL;
	}

	return 0;
}

static struct snd_soc_dai_driver renoir_sof_dai[] = {
	[I2S_BT_INSTANCE] = {
		.id = I2S_BT_INSTANCE,
		.name = "acp-sof-bt",
		.playback = {
			.rates = SNDRV_PCM_RATE_8000_96000,
			.formats = SNDRV_PCM_FMTBIT_S16_LE | SNDRV_PCM_FMTBIT_S8 |
				   SNDRV_PCM_FMTBIT_U8 | SNDRV_PCM_FMTBIT_S32_LE,
			.channels_min = 2,
			.channels_max = 8,
			.rate_min = 8000,
			.rate_max = 96000,
		},
		.capture = {
			.rates = SNDRV_PCM_RATE_8000_48000,
			.formats = SNDRV_PCM_FMTBIT_S16_LE | SNDRV_PCM_FMTBIT_S8 |
				   SNDRV_PCM_FMTBIT_U8 | SNDRV_PCM_FMTBIT_S32_LE,
			/* Supporting only stereo for I2S BT controller capture */
			.channels_min = 2,
			.channels_max = 2,
			.rate_min = 8000,
			.rate_max = 48000,
		},
		.probe = &renoir_dai_probe,
	},

	[I2S_SP_INSTANCE] = {
		.id = I2S_SP_INSTANCE,
		.name = "acp-sof-sp",
		.playback = {
			.rates = SNDRV_PCM_RATE_8000_96000,
			.formats = SNDRV_PCM_FMTBIT_S16_LE | SNDRV_PCM_FMTBIT_S8 |
				   SNDRV_PCM_FMTBIT_U8 | SNDRV_PCM_FMTBIT_S32_LE,
			.channels_min = 2,
			.channels_max = 8,
			.rate_min = 8000,
			.rate_max = 96000,
		},
		.capture = {
			.rates = SNDRV_PCM_RATE_8000_48000,
			.formats = SNDRV_PCM_FMTBIT_S16_LE | SNDRV_PCM_FMTBIT_S8 |
				   SNDRV_PCM_FMTBIT_U8 | SNDRV_PCM_FMTBIT_S32_LE,
			/* Supporting only stereo for I2S SP controller capture */
			.channels_min = 2,
			.channels_max = 2,
			.rate_min = 8000,
			.rate_max = 48000,
		},
		.probe = &renoir_dai_probe,
	},

	[PDM_DMIC_INSTANCE] = {
		.id = PDM_DMIC_INSTANCE,
		.name = "acp-sof-dmic",
		.capture = {
			.rates = SNDRV_PCM_RATE_8000_48000,
			.formats = SNDRV_PCM_FMTBIT_S32_LE,
			.channels_min = 2,
			.channels_max = 4,
			.rate_min = 8000,
			.rate_max = 48000,
		},
	},
};

static struct snd_soc_acpi_mach *amd_sof_machine_select(struct snd_sof_dev *sdev)
{
	struct snd_sof_pdata *sof_pdata = sdev->pdata;
	const struct sof_dev_desc *desc = sof_pdata->desc;
	struct snd_soc_acpi_mach *mach;

	mach = snd_soc_acpi_find_machine(desc->machines);
	if (!mach) {
		dev_warn(sdev->dev, "No matching ASoC machine driver found\n");
		return NULL;
	}

	sof_pdata->tplg_filename = mach->sof_tplg_filename;
	sof_pdata->fw_filename = mach->fw_filename;

	return mach;
}

/**
 * amd_sof_ipc_dump() - This function is called when IPC tx times out.
 * @sdev: SOF device.
 */
void amd_sof_ipc_dump(struct snd_sof_dev *sdev)
{
	u32 dsp_msg_write = sdev->debug_box.offset +
			    offsetof(struct scratch_ipc_conf, sof_dsp_msg_write);
	u32 dsp_ack_write = sdev->debug_box.offset +
			    offsetof(struct scratch_ipc_conf, sof_dsp_ack_write);
	u32 host_msg_write = sdev->debug_box.offset +
			     offsetof(struct scratch_ipc_conf, sof_host_msg_write);
	u32 host_ack_write = sdev->debug_box.offset +
			     offsetof(struct scratch_ipc_conf, sof_host_ack_write);
	u32 dsp_msg, dsp_ack, host_msg, host_ack, irq_stat;

	dsp_msg = snd_sof_dsp_read(sdev, ACP_DSP_BAR, ACP_SCRATCH_REG_0 + dsp_msg_write);
	dsp_ack = snd_sof_dsp_read(sdev, ACP_DSP_BAR, ACP_SCRATCH_REG_0 + dsp_ack_write);
	host_msg = snd_sof_dsp_read(sdev, ACP_DSP_BAR, ACP_SCRATCH_REG_0 + host_msg_write);
	host_ack = snd_sof_dsp_read(sdev, ACP_DSP_BAR, ACP_SCRATCH_REG_0 + host_ack_write);
	irq_stat = snd_sof_dsp_read(sdev, ACP_DSP_BAR, ACP_DSP_SW_INTR_STAT);

	dev_err(sdev->dev,
		"dsp_msg = %#x dsp_ack = %#x host_msg = %#x host_ack = %#x irq_stat = %#x\n",
		dsp_msg, dsp_ack, host_msg, host_ack, irq_stat);
}

/**
 * amd_get_registers() - This function is called in case of DSP oops
 * in order to gather information about the registers, filename and
 * linenumber and stack.
 * @sdev: SOF device.
 * @xoops: Stores information about registers.
 * @panic_info: Stores information about filename and line number.
 * @stack: Stores the stack dump.
 * @stack_words: Size of the stack dump.
 */
static void amd_get_registers(struct snd_sof_dev *sdev,
			      struct sof_ipc_dsp_oops_xtensa *xoops,
			      struct sof_ipc_panic_info *panic_info,
			      u32 *stack, size_t stack_words)
{
	u32 offset = sdev->dsp_oops_offset;

	/* first read registers */
	acp_mailbox_read(sdev, offset, xoops, sizeof(*xoops));

	/* then get panic info */
	if (xoops->arch_hdr.totalsize > EXCEPT_MAX_HDR_SIZE) {
		dev_err(sdev->dev, "invalid header size 0x%x. FW oops is bogus\n",
			xoops->arch_hdr.totalsize);
		return;
	}

	offset += xoops->arch_hdr.totalsize;
	acp_mailbox_read(sdev, offset, panic_info, sizeof(*panic_info));

	/* then get the stack */
	offset += sizeof(*panic_info);
	acp_mailbox_read(sdev, offset, stack, stack_words * sizeof(u32));
}

/**
 * amd_sof_dump() - This function is called when a panic message is
 * received from the firmware.
 * @sdev: SOF device.
 * @flags: parameter not used but required by ops prototype
 */
void amd_sof_dump(struct snd_sof_dev *sdev, u32 flags)
{
	struct sof_ipc_dsp_oops_xtensa xoops;
	struct sof_ipc_panic_info panic_info;
	u32 stack[AMD_STACK_DUMP_SIZE];
	u32 status;

	/* Get information about the panic status from the debug box area.
	 * Compute the trace point based on the status.
	 */
	if (sdev->dsp_oops_offset > sdev->debug_box.offset) {
		acp_mailbox_read(sdev, sdev->debug_box.offset, &status, sizeof(u32));
	} else {
		/* Read DSP Panic status from dsp_box.
		 * As window information for exception box offset and size is not available
		 * before FW_READY
		 */
		acp_mailbox_read(sdev, sdev->dsp_box.offset, &status, sizeof(u32));
		sdev->dsp_oops_offset = sdev->dsp_box.offset + sizeof(status);
	}

	/* Get information about the registers, the filename and line
	 * number and the stack.
	 */
	amd_get_registers(sdev, &xoops, &panic_info, stack, AMD_STACK_DUMP_SIZE);

	/* Print the information to the console */
	snd_sof_get_status(sdev, status, status, &xoops,
				 &panic_info, stack, AMD_STACK_DUMP_SIZE);
}

/* AMD Renoir DSP ops */
const struct snd_sof_dsp_ops sof_renoir_ops = {
	/* probe and remove */
	.probe			= amd_sof_acp_probe,
	.remove			= amd_sof_acp_remove,

	/* Register IO */
	.write			= sof_io_write,
	.read			= sof_io_read,

	/* Block IO */
	.block_read		= acp_dsp_block_read,
	.block_write		= acp_dsp_block_write,

	/* Module loading */
	.load_module		= snd_sof_parse_module_memcpy,

	/*Firmware loading */
	.load_firmware		= snd_sof_load_firmware_memcpy,
	.pre_fw_run		= acp_dsp_pre_fw_run,
	.get_bar_index		= acp_get_bar_index,

	/* DSP core boot */
	.run			= acp_sof_dsp_run,

	/*IPC */
	.send_msg		= acp_sof_ipc_send_msg,
	.ipc_msg_data		= acp_sof_ipc_msg_data,
	.ipc_pcm_params		= acp_sof_ipc_pcm_params,
	.get_mailbox_offset	= acp_sof_ipc_get_mailbox_offset,
	.get_window_offset      = acp_sof_ipc_get_window_offset,
	.irq_thread		= acp_sof_ipc_irq_thread,
	.fw_ready		= sof_fw_ready,

	/* DAI drivers */
	.drv			= renoir_sof_dai,
	.num_drv		= ARRAY_SIZE(renoir_sof_dai),

	/* stream callbacks */
	.pcm_open		= acp_pcm_open,
	.pcm_close		= acp_pcm_close,
	.pcm_hw_params		= acp_pcm_hw_params,
	.pcm_pointer		= acp_pcm_pointer,

	.hw_info		= SNDRV_PCM_INFO_MMAP |
				  SNDRV_PCM_INFO_MMAP_VALID |
				  SNDRV_PCM_INFO_INTERLEAVED |
				  SNDRV_PCM_INFO_PAUSE |
				  SNDRV_PCM_INFO_NO_PERIOD_WAKEUP,

	/* Machine driver callbacks */
	.machine_select		= amd_sof_machine_select,
	.machine_register	= sof_machine_register,
	.machine_unregister	= sof_machine_unregister,

	/* Trace Logger */
	.trace_init		= acp_sof_trace_init,
	.trace_release		= acp_sof_trace_release,

	.ipc_dump		= amd_sof_ipc_dump,
	.dbg_dump		= amd_sof_dump,
	.debugfs_add_region_item = snd_sof_debugfs_add_region_item_iomem,
	.dsp_arch_ops = &sof_xtensa_arch_ops,
};
EXPORT_SYMBOL(sof_renoir_ops);

MODULE_IMPORT_NS(SND_SOC_SOF_AMD_COMMON);
MODULE_IMPORT_NS(SND_SOC_SOF_XTENSA);
MODULE_DESCRIPTION("RENOIR SOF Driver");
MODULE_LICENSE("Dual BSD/GPL");
