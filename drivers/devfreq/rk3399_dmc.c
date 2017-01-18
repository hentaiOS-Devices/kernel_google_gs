// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2016, Fuzhou Rockchip Electronics Co., Ltd.
 * Author: Lin Huang <hl@rock-chips.com>
 */

#include <linux/arm-smccc.h>
#include <linux/bitfield.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/devfreq.h>
#include <linux/devfreq-event.h>
#include <linux/interrupt.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pm_opp.h>
#include <linux/regmap.h>
#include <linux/regulator/consumer.h>
#include <linux/rwsem.h>
#include <linux/suspend.h>
#include <linux/workqueue.h>

#include <soc/rockchip/rk3399_grf.h>
#include <soc/rockchip/rockchip_sip.h>

#include "event/rockchip-dfi.h"
#include "governor.h"

#define NS_TO_CYCLE(NS, MHz)				(((NS) * (MHz)) / NSEC_PER_USEC)

#define RK3399_SET_ODT_PD_0_SR_IDLE			GENMASK(7, 0)
#define RK3399_SET_ODT_PD_0_SR_MC_GATE_IDLE		GENMASK(15, 8)
#define RK3399_SET_ODT_PD_0_STANDBY_IDLE		GENMASK(31, 16)

#define RK3399_SET_ODT_PD_1_PD_IDLE			GENMASK(11, 0)
#define RK3399_SET_ODT_PD_1_SRPD_LITE_IDLE		GENMASK(27, 16)

#define RK3399_SET_ODT_PD_2_ODT_ENABLE			BIT(0)

#define DFI_DEFAULT_TARGET_LOAD		15
#define DFI_DEFAULT_HYSTERESIS		3
#define DFI_DEFAULT_DOWN_THROTTLE_MS	200

struct rk3399_dmcfreq {
	struct device *dev;
	struct devfreq *devfreq;
	struct devfreq_dev_profile profile;
	struct clk *dmc_clk;
	struct devfreq_event_dev *edev;
	struct mutex lock;
	struct regulator *vdd_center;
	struct regmap *regmap_pmu;
	unsigned long rate, target_rate;
	unsigned long volt, target_volt;
	unsigned int odt_dis_freq;

	unsigned int pd_idle_ns;
	unsigned int sr_idle_ns;
	unsigned int sr_mc_gate_idle_ns;
	unsigned int srpd_lite_idle_ns;
	unsigned int standby_idle_ns;
	unsigned int ddr3_odt_dis_freq;
	unsigned int lpddr3_odt_dis_freq;
	unsigned int lpddr4_odt_dis_freq;

	unsigned int pd_idle_dis_freq;
	unsigned int sr_idle_dis_freq;
	unsigned int sr_mc_gate_idle_dis_freq;
	unsigned int srpd_lite_idle_dis_freq;
	unsigned int standby_idle_dis_freq;

	struct delayed_work throttle_work;
	unsigned int target_load;
	unsigned int hysteresis;
	unsigned int down_throttle_ms;
};

static int rk3399_dfi_get_target(struct devfreq *devfreq, unsigned long *freq)
{
	struct rk3399_dmcfreq *dmcfreq = dev_get_drvdata(devfreq->dev.parent);
	struct devfreq_dev_status *stat;
	unsigned long long a;
	int err;

	if (devfreq->stop_polling) {
		*freq = devfreq->suspend_freq;
		return 0;
	}

	err = devfreq_update_stats(devfreq);
	if (err)
		return err;

	stat = &devfreq->last_status;

	if (stat->total_time == 0) {
		*freq = DEVFREQ_MAX_FREQ;
		return 0;
	}

	if (stat->busy_time >= (1 << 24) || stat->total_time >= (1 << 24)) {
		stat->busy_time >>= 7;
		stat->total_time >>= 7;
	}

	a = stat->busy_time * stat->current_frequency;
	a = div_u64(a, stat->total_time);
	a *= 100;
	a = div_u64(a, dmcfreq->target_load);
	*freq = (unsigned long)a;

	return 0;
}

static void rk3399_dfi_calc_top_threshold(struct devfreq *devfreq)
{
	struct rk3399_dmcfreq *dmcfreq = dev_get_drvdata(devfreq->dev.parent);
	unsigned int percent;

	if (devfreq->scaling_max_freq && dmcfreq->rate >= devfreq->scaling_max_freq)
		percent = 100;
	else
		percent = dmcfreq->target_load + dmcfreq->hysteresis;
	rockchip_dfi_calc_top_threshold(dmcfreq->edev, dmcfreq->rate, percent);
}

static void rk3399_dfi_calc_floor_threshold(struct devfreq *devfreq)
{
	struct rk3399_dmcfreq *dmcfreq = dev_get_drvdata(devfreq->dev.parent);
	struct dev_pm_opp *opp;
	unsigned long rate;
	unsigned int percent;

	if (dmcfreq->rate <= devfreq->scaling_min_freq)
		percent = 0;
	else
		percent = dmcfreq->target_load - dmcfreq->hysteresis;

	rate = dmcfreq->rate - 1;
	opp = devfreq_recommended_opp(devfreq->dev.parent, &rate,
				      DEVFREQ_FLAG_LEAST_UPPER_BOUND);
	rate = dev_pm_opp_get_freq(opp);
	dev_pm_opp_put(opp);
	rockchip_dfi_calc_floor_threshold(dmcfreq->edev, rate, percent);
}

static int rk3399_dfi_event_handler(struct devfreq *devfreq, unsigned int event,
				    void *data)
{
	struct rk3399_dmcfreq *dmcfreq = dev_get_drvdata(devfreq->dev.parent);
	struct devfreq_event_dev *edev = dmcfreq->edev;
	int ret;

	switch (event) {
	case DEVFREQ_GOV_START:
		ret = devfreq_event_enable_edev(edev);
		if (ret < 0) {
			dev_err(&devfreq->dev, "Unable to enable DFI edev\n");
			return ret;
		}

		devfreq->data = dmcfreq;
		rk3399_dfi_calc_top_threshold(devfreq);
		rk3399_dfi_calc_floor_threshold(devfreq);
		ret = devfreq_event_set_event(edev);
		if (ret < 0) {
			dev_err(&devfreq->dev, "Unable to set DFI event\n");
			devfreq->data = NULL;
			devfreq_event_disable_edev(edev);
			return ret;
		}

		break;
	case DEVFREQ_GOV_STOP:
		ret = devfreq_event_disable_edev(edev);
		if (ret < 0) {
			dev_err(&devfreq->dev, "Unable to disable DFI edev\n");
			return ret;
		}

		devfreq->data = NULL;
		break;
	case DEVFREQ_GOV_SUSPEND:
		ret = devfreq_event_disable_edev(edev);
		if (ret < 0) {
			dev_err(&devfreq->dev, "Unable to disable DFI edev\n");
			return ret;
		}

		devfreq_monitor_suspend(devfreq);
		break;
	case DEVFREQ_GOV_RESUME:
		ret = devfreq_event_enable_edev(edev);
		if (ret < 0) {
			dev_err(&devfreq->dev, "Unable to enable DFI edev\n");
			return ret;
		}

		devfreq_monitor_resume(devfreq);
		rk3399_dfi_calc_top_threshold(devfreq);
		rk3399_dfi_calc_floor_threshold(devfreq);
		ret = devfreq_event_set_event(edev);
		if (ret < 0) {
			dev_err(&devfreq->dev, "Unable to set DFI event\n");
			devfreq->data = NULL;
			devfreq_event_disable_edev(edev);
			return ret;
		}

		break;
	default:
		break;
	}

	return 0;
}

static struct devfreq_governor rk3399_dfi_governor = {
	.name = "rk3399-dfi",
	.get_target_freq = rk3399_dfi_get_target,
	.event_handler = rk3399_dfi_event_handler,
	.flags = DEVFREQ_GOV_FLAG_IRQ_DRIVEN,
};

static void rk3399_dmcfreq_throttle_work(struct work_struct *work)
{
	struct delayed_work *dwork = container_of(work, struct delayed_work,
						  work);
	struct rk3399_dmcfreq *dmcfreq = container_of(dwork,
						      struct rk3399_dmcfreq,
						      throttle_work);

	rk3399_dfi_calc_floor_threshold(dmcfreq->devfreq);
	devfreq_event_set_event(dmcfreq->edev);
}

static int rk3399_dmcfreq_target(struct device *dev, unsigned long *freq,
				 u32 flags)
{
	struct rk3399_dmcfreq *dmcfreq = dev_get_drvdata(dev);
	struct dev_pm_opp *opp;
	struct devfreq_event_dev *edev;
	unsigned long old_clk_rate = dmcfreq->rate;
	unsigned long target_volt, target_rate;
	unsigned int ddrcon_mhz;
	struct arm_smccc_res res;
	int err;

	u32 odt_pd_arg0 = 0;
	u32 odt_pd_arg1 = 0;
	u32 odt_pd_arg2 = 0;

	opp = devfreq_recommended_opp(dev, freq, flags);
	if (IS_ERR(opp))
		return PTR_ERR(opp);

	target_rate = dev_pm_opp_get_freq(opp);
	target_volt = dev_pm_opp_get_voltage(opp);
	dev_pm_opp_put(opp);

	if (dmcfreq->rate == target_rate)
		return 0;

	mutex_lock(&dmcfreq->lock);

	/*
	 * Some idle parameters may be based on the DDR controller clock, which
	 * is half of the DDR frequency.
	 * pd_idle and standby_idle are based on the controller clock cycle.
	 * sr_idle_cycle, sr_mc_gate_idle_cycle, and srpd_lite_idle_cycle
	 * are based on the 1024 controller clock cycle
	 */
	ddrcon_mhz = target_rate / USEC_PER_SEC / 2;

	u32p_replace_bits(&odt_pd_arg1,
			  NS_TO_CYCLE(dmcfreq->pd_idle_ns, ddrcon_mhz),
			  RK3399_SET_ODT_PD_1_PD_IDLE);
	u32p_replace_bits(&odt_pd_arg0,
			  NS_TO_CYCLE(dmcfreq->standby_idle_ns, ddrcon_mhz),
			  RK3399_SET_ODT_PD_0_STANDBY_IDLE);
	u32p_replace_bits(&odt_pd_arg0,
			  DIV_ROUND_UP(NS_TO_CYCLE(dmcfreq->sr_idle_ns,
						   ddrcon_mhz), 1024),
			  RK3399_SET_ODT_PD_0_SR_IDLE);
	u32p_replace_bits(&odt_pd_arg0,
			  DIV_ROUND_UP(NS_TO_CYCLE(dmcfreq->sr_mc_gate_idle_ns,
						   ddrcon_mhz), 1024),
			  RK3399_SET_ODT_PD_0_SR_MC_GATE_IDLE);
	u32p_replace_bits(&odt_pd_arg1,
			  DIV_ROUND_UP(NS_TO_CYCLE(dmcfreq->srpd_lite_idle_ns,
						   ddrcon_mhz), 1024),
			  RK3399_SET_ODT_PD_1_SRPD_LITE_IDLE);

	if (dmcfreq->regmap_pmu) {
		if (target_rate >= dmcfreq->sr_idle_dis_freq)
			odt_pd_arg0 &= ~RK3399_SET_ODT_PD_0_SR_IDLE;

		if (target_rate >= dmcfreq->sr_mc_gate_idle_dis_freq)
			odt_pd_arg0 &= ~RK3399_SET_ODT_PD_0_SR_MC_GATE_IDLE;

		if (target_rate >= dmcfreq->standby_idle_dis_freq)
			odt_pd_arg0 &= ~RK3399_SET_ODT_PD_0_STANDBY_IDLE;

		if (target_rate >= dmcfreq->pd_idle_dis_freq)
			odt_pd_arg1 &= ~RK3399_SET_ODT_PD_1_PD_IDLE;

		if (target_rate >= dmcfreq->srpd_lite_idle_dis_freq)
			odt_pd_arg1 &= ~RK3399_SET_ODT_PD_1_SRPD_LITE_IDLE;

		if (target_rate >= dmcfreq->odt_dis_freq)
			odt_pd_arg2 |= RK3399_SET_ODT_PD_2_ODT_ENABLE;

		/*
		 * This makes a SMC call to the TF-A to set the DDR PD
		 * (power-down) timings and to enable or disable the
		 * ODT (on-die termination) resistors.
		 */
		arm_smccc_smc(ROCKCHIP_SIP_DRAM_FREQ, odt_pd_arg0, odt_pd_arg1,
			      ROCKCHIP_SIP_CONFIG_DRAM_SET_ODT_PD, odt_pd_arg2,
			      0, 0, 0, &res);
	}

	/*
	 * If frequency scaling from low to high, adjust voltage first.
	 * If frequency scaling from high to low, adjust frequency first.
	 */
	if (old_clk_rate < target_rate) {
		err = regulator_set_voltage(dmcfreq->vdd_center, target_volt,
					    target_volt);
		if (err) {
			dev_err(dev, "Cannot set voltage %lu uV\n",
				target_volt);
			goto out;
		}
	}

	err = clk_set_rate(dmcfreq->dmc_clk, target_rate);
	if (err) {
		dev_err(dev, "Cannot set frequency %lu (%d)\n", target_rate,
			err);
		regulator_set_voltage(dmcfreq->vdd_center, dmcfreq->volt,
				      dmcfreq->volt);
		goto out;
	}

	/*
	 * Check the dpll rate,
	 * There only two result we will get,
	 * 1. Ddr frequency scaling fail, we still get the old rate.
	 * 2. Ddr frequency scaling sucessful, we get the rate we set.
	 */
	dmcfreq->rate = clk_get_rate(dmcfreq->dmc_clk);

	/* If get the incorrect rate, set voltage to old value. */
	if (dmcfreq->rate != target_rate) {
		dev_err(dev, "Got wrong frequency, Request %lu, Current %lu\n",
			target_rate, dmcfreq->rate);
		regulator_set_voltage(dmcfreq->vdd_center, dmcfreq->volt,
				      dmcfreq->volt);
		goto out;
	} else if (old_clk_rate > target_rate)
		err = regulator_set_voltage(dmcfreq->vdd_center, target_volt,
					    target_volt);
	if (err)
		dev_err(dev, "Cannot set voltage %lu uV\n", target_volt);

	dmcfreq->rate = target_rate;
	dmcfreq->volt = target_volt;

	edev = dmcfreq->edev;
	if (old_clk_rate < target_rate) {
		cancel_delayed_work_sync(&dmcfreq->throttle_work);
		rockchip_dfi_calc_floor_threshold(edev, 0, 0);
		schedule_delayed_work(&dmcfreq->throttle_work,
				msecs_to_jiffies(dmcfreq->down_throttle_ms));
	} else {
		rk3399_dfi_calc_floor_threshold(dmcfreq->devfreq);
	}

	rk3399_dfi_calc_top_threshold(dmcfreq->devfreq);
	devfreq_event_set_event(dmcfreq->edev);
out:
	mutex_unlock(&dmcfreq->lock);
	return err;
}

static int rk3399_dmcfreq_get_dev_status(struct device *dev,
					 struct devfreq_dev_status *stat)
{
	struct rk3399_dmcfreq *dmcfreq = dev_get_drvdata(dev);
	struct devfreq_event_data edata;
	int ret = 0;

	ret = devfreq_event_get_event(dmcfreq->edev, &edata);
	if (ret < 0)
		return ret;

	stat->current_frequency = dmcfreq->rate;
	stat->busy_time = edata.load_count;
	stat->total_time = edata.total_count;

	return ret;
}

static int rk3399_dmcfreq_get_cur_freq(struct device *dev, unsigned long *freq)
{
	struct rk3399_dmcfreq *dmcfreq = dev_get_drvdata(dev);

	*freq = dmcfreq->rate;

	return 0;
}

static __maybe_unused int rk3399_dmcfreq_suspend(struct device *dev)
{
	struct rk3399_dmcfreq *dmcfreq = dev_get_drvdata(dev);
	int ret;

	ret = devfreq_suspend_device(dmcfreq->devfreq);
	if (ret < 0) {
		dev_err(dev, "failed to suspend the devfreq devices\n");
		return ret;
	}

	return 0;
}

static __maybe_unused int rk3399_dmcfreq_resume(struct device *dev)
{
	struct rk3399_dmcfreq *dmcfreq = dev_get_drvdata(dev);
	int ret;

	ret = devfreq_resume_device(dmcfreq->devfreq);
	if (ret < 0) {
		dev_err(dev, "failed to resume the devfreq devices\n");
		return ret;
	}

	return ret;
}

static SIMPLE_DEV_PM_OPS(rk3399_dmcfreq_pm, rk3399_dmcfreq_suspend,
			 rk3399_dmcfreq_resume);

static int rk3399_dmcfreq_of_props(struct rk3399_dmcfreq *data,
				   struct device_node *np)
{
	int ret = 0;

	/*
	 * These are all optional, and serve as minimum bounds. Give them large
	 * (i.e., never "disabled") values if the DT doesn't specify one.
	 */
	data->pd_idle_dis_freq =
		data->sr_idle_dis_freq =
		data->sr_mc_gate_idle_dis_freq =
		data->srpd_lite_idle_dis_freq =
		data->standby_idle_dis_freq = UINT_MAX;

	ret |= of_property_read_u32(np, "rockchip,pd-idle-ns",
				    &data->pd_idle_ns);
	ret |= of_property_read_u32(np, "rockchip,sr-idle-ns",
				    &data->sr_idle_ns);
	ret |= of_property_read_u32(np, "rockchip,sr-mc-gate-idle-ns",
				    &data->sr_mc_gate_idle_ns);
	ret |= of_property_read_u32(np, "rockchip,srpd-lite-idle-ns",
				    &data->srpd_lite_idle_ns);
	ret |= of_property_read_u32(np, "rockchip,standby-idle-ns",
				    &data->standby_idle_ns);
	ret |= of_property_read_u32(np, "rockchip,ddr3_odt_dis_freq",
				    &data->ddr3_odt_dis_freq);
	ret |= of_property_read_u32(np, "rockchip,lpddr3_odt_dis_freq",
				    &data->lpddr3_odt_dis_freq);
	ret |= of_property_read_u32(np, "rockchip,lpddr4_odt_dis_freq",
				    &data->lpddr4_odt_dis_freq);

	ret |= of_property_read_u32(np, "rockchip,pd-idle-dis-freq-hz",
				    &data->pd_idle_dis_freq);
	ret |= of_property_read_u32(np, "rockchip,sr-idle-dis-freq-hz",
				    &data->sr_idle_dis_freq);
	ret |= of_property_read_u32(np, "rockchip,sr-mc-gate-idle-dis-freq-hz",
				    &data->sr_mc_gate_idle_dis_freq);
	ret |= of_property_read_u32(np, "rockchip,srpd-lite-idle-dis-freq-hz",
				    &data->srpd_lite_idle_dis_freq);
	ret |= of_property_read_u32(np, "rockchip,standby-idle-dis-freq-hz",
				    &data->standby_idle_dis_freq);

	return ret;
}

static int rk3399_dmcfreq_probe(struct platform_device *pdev)
{
	struct arm_smccc_res res;
	struct device *dev = &pdev->dev;
	struct device_node *np = pdev->dev.of_node, *node;
	struct rk3399_dmcfreq *data;
	int ret;
	struct dev_pm_opp *opp;
	u32 ddr_type;
	u32 val;

	data = devm_kzalloc(dev, sizeof(struct rk3399_dmcfreq), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	mutex_init(&data->lock);

	data->vdd_center = devm_regulator_get(dev, "center");
	if (IS_ERR(data->vdd_center))
		return dev_err_probe(dev, PTR_ERR(data->vdd_center),
				     "Cannot get the regulator \"center\"\n");

	data->dmc_clk = devm_clk_get(dev, "dmc_clk");
	if (IS_ERR(data->dmc_clk))
		return dev_err_probe(dev, PTR_ERR(data->dmc_clk),
				     "Cannot get the clk dmc_clk\n");

	data->edev = devfreq_event_get_edev_by_phandle(dev, "devfreq-events", 0);
	if (IS_ERR(data->edev))
		return -EPROBE_DEFER;

	rk3399_dmcfreq_of_props(data, np);

	node = of_parse_phandle(np, "rockchip,pmu", 0);
	if (!node)
		goto no_pmu;

	data->regmap_pmu = syscon_node_to_regmap(node);
	of_node_put(node);
	if (IS_ERR(data->regmap_pmu)) {
		ret = PTR_ERR(data->regmap_pmu);
		goto out;
	}

	regmap_read(data->regmap_pmu, RK3399_PMUGRF_OS_REG2, &val);
	ddr_type = (val >> RK3399_PMUGRF_DDRTYPE_SHIFT) &
		    RK3399_PMUGRF_DDRTYPE_MASK;

	switch (ddr_type) {
	case RK3399_PMUGRF_DDRTYPE_DDR3:
		data->odt_dis_freq = data->ddr3_odt_dis_freq;
		break;
	case RK3399_PMUGRF_DDRTYPE_LPDDR3:
		data->odt_dis_freq = data->lpddr3_odt_dis_freq;
		break;
	case RK3399_PMUGRF_DDRTYPE_LPDDR4:
		data->odt_dis_freq = data->lpddr4_odt_dis_freq;
		break;
	default:
		ret = -EINVAL;
		goto out;
	}

no_pmu:
	arm_smccc_smc(ROCKCHIP_SIP_DRAM_FREQ, 0, 0,
		      ROCKCHIP_SIP_CONFIG_DRAM_INIT,
		      0, 0, 0, 0, &res);

	/*
	 * We add a devfreq driver to our parent since it has a device tree node
	 * with operating points.
	 */
	if (devm_pm_opp_of_add_table(dev)) {
		dev_err(dev, "Invalid operating-points in device tree.\n");
		ret = -EINVAL;
		goto out;
	}

	data->target_load = DFI_DEFAULT_TARGET_LOAD;
	data->hysteresis = DFI_DEFAULT_HYSTERESIS;
	data->down_throttle_ms = DFI_DEFAULT_DOWN_THROTTLE_MS;
	INIT_DELAYED_WORK(&data->throttle_work, rk3399_dmcfreq_throttle_work);

	data->rate = clk_get_rate(data->dmc_clk);

	opp = devfreq_recommended_opp(dev, &data->rate, 0);
	if (IS_ERR(opp)) {
		ret = PTR_ERR(opp);
		goto out;
	}

	data->rate = dev_pm_opp_get_freq(opp);
	data->volt = dev_pm_opp_get_voltage(opp);
	dev_pm_opp_put(opp);

	data->profile = (struct devfreq_dev_profile) {
		.polling_ms	= 0,
		.target		= rk3399_dmcfreq_target,
		.get_dev_status	= rk3399_dmcfreq_get_dev_status,
		.get_cur_freq	= rk3399_dmcfreq_get_cur_freq,
		.initial_freq	= data->rate,
	};

	ret = devfreq_add_governor(&rk3399_dfi_governor);
	if (ret < 0) {
		dev_err(dev, "Failed to add dfi governor\n");
		goto out;
	}

	data->dev = dev;
	platform_set_drvdata(pdev, data);
	data->devfreq = devm_devfreq_add_device(dev,
					   &data->profile,
					   "rk3399-dfi",
					   NULL);
	if (IS_ERR(data->devfreq)) {
		ret = PTR_ERR(data->devfreq);
		goto out;
	}

	devm_devfreq_register_opp_notifier(dev, data->devfreq);

	/* The dfi irq won't trigger a frequency update until this is done. */
	dev_set_drvdata(&data->edev->dev, data->devfreq);

	return 0;

out:
	return ret;
}

static int rk3399_dmcfreq_remove(struct platform_device *pdev)
{
	return devfreq_remove_governor(&rk3399_dfi_governor);
}

static const struct of_device_id rk3399dmc_devfreq_of_match[] = {
	{ .compatible = "rockchip,rk3399-dmc" },
	{ },
};
MODULE_DEVICE_TABLE(of, rk3399dmc_devfreq_of_match);

static struct platform_driver rk3399_dmcfreq_driver = {
	.probe	= rk3399_dmcfreq_probe,
	.remove = rk3399_dmcfreq_remove,
	.driver = {
		.name	= "rk3399-dmc-freq",
		.pm	= &rk3399_dmcfreq_pm,
		.of_match_table = rk3399dmc_devfreq_of_match,
	},
};
module_platform_driver(rk3399_dmcfreq_driver);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Lin Huang <hl@rock-chips.com>");
MODULE_DESCRIPTION("RK3399 dmcfreq driver with devfreq framework");
