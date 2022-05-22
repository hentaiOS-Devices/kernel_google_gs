// SPDX-License-Identifier: GPL-2.0
/*
 * Core code for non-thermal throttling
 *
 * Copyright (C) 2018-2022 Google, Inc.
 */

#include <linux/cpu.h>
#include <linux/cpufreq.h>
#include <linux/debugfs.h>
#include <linux/devfreq.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/lockdep.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pm_opp.h>
#include <linux/pm_qos.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/throttler.h>

/*
 * Non-thermal throttling: throttling of system components in response to
 * external events (e.g. high battery discharge current).
 *
 * The throttler supports throttling through cpufreq and devfreq. Multiple
 * levels of throttling can be configured. At level 0 no throttling is
 * active on behalf of the throttler, for values > 0 throttling is typically
 * configured to be increasingly aggressive with each level.
 * The number of throttling levels is not limited by the throttler (though
 * it is likely limited by the throttling devices). It is not necessary to
 * configure the same number of levels for all throttling devices. If the
 * requested throttling level for a device is higher than the maximum level
 * of the device the throttler will select the maximum throttling level of
 * the device.
 *
 * Non-thermal throttling is split in two parts:
 *
 * - throttler core
 *   - parses the thermal policy
 *   - applies throttling settings for a requested level of throttling
 *
 * - event monitor driver
 *   - monitors events that trigger throttling
 *   - determines the throttling level (often limited to on/off)
 *   - asks throttler core to apply throttling settings
 *
 * It is possible for a system to have more than one throttler and the
 * throttlers may make use of the same throttling devices, in case of
 * conflicting settings for a device the more aggressive values will be
 * applied.
 */

#define ci_to_throttler(ci)                                                    \
	container_of(ci, struct throttler, devfreq_class_iface)

struct thr_freq_table {
	uint32_t *freqs;
	int n_entries;
};

struct throttler_target {
	struct device *dev;
	struct cpufreq_policy *policy;
	struct dev_pm_qos_request dev_req;
	struct freq_qos_request freq_req;
	struct thr_freq_table freq_table;
	struct list_head node;
};

struct throttler {
	struct device *dev;
	unsigned int level;
	struct list_head targets;
	struct notifier_block cpufreq_nb;
	struct class_interface devfreq_class_iface;
	struct mutex lock;
	struct dentry *debugfs_dir;
};

static inline int cmp_freqs(const void *a, const void *b)
{
	const uint32_t *pa = a, *pb = b;

	if (*pa < *pb)
		return 1;
	else if (*pa > *pb)
		return -1;

	return 0;
}

/* In kHz. */
static s32 thr_get_throttling_freq(struct thr_freq_table *ft,
				   unsigned int level)
{
	if (level == 0)
		return PM_QOS_MAX_FREQUENCY_DEFAULT_VALUE;

	if (level <= ft->n_entries)
		return ft->freqs[level - 1] / 1000;
	else
		return ft->freqs[ft->n_entries - 1] / 1000;
}

static int thr_init_freq_table(struct throttler *thr, struct device *opp_dev,
			       struct thr_freq_table *ft)
{
	struct device_node *np_opp_desc;
	int n_opps;
	int n_thr_opps;
	int i;
	uint32_t *freqs;
	int n_freqs = 0;
	int err = 0;

	np_opp_desc = dev_pm_opp_of_get_opp_desc_node(opp_dev);
	if (!np_opp_desc)
		return -EINVAL;

	n_opps = of_get_child_count(np_opp_desc);
	if (!n_opps) {
		err = -EINVAL;
		goto out_node_put;
	}

	freqs = kzalloc(n_opps * sizeof(uint32_t), GFP_KERNEL);
	if (!freqs) {
		err = -ENOMEM;
		goto out_node_put;
	}

	n_thr_opps = of_property_count_u32_elems(thr->dev->of_node,
						 "throttler-opps");
	if (n_thr_opps <= 0) {
		dev_err(thr->dev, "No OPPs configured for throttling\n");
		err = -EINVAL;
		goto out_free;
	}

	for (i = 0; i < n_thr_opps; i++) {
		struct device_node *np_opp;
		u64 rate;

		np_opp = of_parse_phandle(thr->dev->of_node, "throttler-opps",
					  i);
		if (!np_opp) {
			dev_err(thr->dev,
				"failed to parse 'throttler-opps' phandle %d\n",
				i);
			continue;
		}

		if (of_get_parent(np_opp) != np_opp_desc) {
			of_node_put(np_opp);
			continue;
		}

		err = of_property_read_u64(np_opp, "opp-hz", &rate);
		if (!err) {
			freqs[n_freqs] = rate;
			n_freqs++;

			dev_dbg(thr->dev,
				"OPP %s (%llu MHz) is used for throttling\n",
				np_opp->full_name, div_u64(rate, 1000000));
		} else {
			dev_err(thr->dev, "opp-hz not found: %s\n",
				np_opp->full_name);
		}

		of_node_put(np_opp);
	}

	if (n_freqs > 0) {
		/* sort frequencies in descending order */
		sort(freqs, n_freqs, sizeof(*freqs), cmp_freqs, NULL);

		ft->n_entries = n_freqs;
		ft->freqs = devm_kzalloc(thr->dev, n_freqs * sizeof(*freqs),
					 GFP_KERNEL);
		if (!ft->freqs) {
			err = -ENOMEM;
			goto out_free;
		}

		memcpy(ft->freqs, freqs, n_freqs * sizeof(*freqs));
	} else {
		err = -ENODEV;
	}

out_free:
	kfree(freqs);

out_node_put:
	of_node_put(np_opp_desc);

	return err;
}

static void thr_update_throttling(struct throttler *thr)
{
	struct throttler_target *target;
	unsigned long clamp_freq;

	lockdep_assert_held(&thr->lock);

	list_for_each_entry(target, &thr->targets, node) {
		int err;

		clamp_freq = thr_get_throttling_freq(&target->freq_table,
						     thr->level);
		if (target->dev) {
			dev_dbg(thr->dev, "Clamping target '%s' to %lu kHz\n",
				dev_name(target->dev), clamp_freq);
			err = dev_pm_qos_update_request(&target->dev_req,
							clamp_freq);
			if (err < 0)
				dev_err(thr->dev,
					"Failed to set QoS for device '%s' / %lu kHz\n",
					dev_name(target->dev), clamp_freq);
		} else {
			struct cpufreq_policy *policy = target->policy;

			dev_dbg(thr->dev,
				"Clamping policy for CPU%d to %lu kHz\n",
				policy->cpu, clamp_freq);
			err = freq_qos_update_request(&target->freq_req,
						      clamp_freq);
			if (err < 0)
				dev_err(thr->dev,
					"Failed to set QoS for CPU%d / %lu kHz\n",
					policy->cpu, clamp_freq);
		}
	}
}

/*
 * Add a 'dev_pm_qos' or 'freq_qos' target for throttling management.
 */
static int thr_add_target(struct throttler *thr, struct device *dev,
			  struct cpufreq_policy *policy,
			  struct thr_freq_table *ft)

{
	struct throttler_target *target;
	int err;

	lockdep_assert_held(&thr->lock);

	/* Provide one of |dev| or |policy| but not both. */
	if (WARN_ON(!(dev || policy) || (dev && policy)))
		return -EINVAL;

	target = devm_kzalloc(thr->dev, sizeof(*target), GFP_KERNEL);
	if (!target)
		return -ENOMEM;

	memcpy(&target->freq_table, ft, sizeof(*ft));

	if (dev) {
		target->dev = dev;
		err = dev_pm_qos_add_request(
			target->dev, &target->dev_req, DEV_PM_QOS_MAX_FREQUENCY,
			PM_QOS_MAX_FREQUENCY_DEFAULT_VALUE);
		if (err < 0)
			goto err;
	} else {
		target->policy = policy;
		err = freq_qos_add_request(&policy->constraints,
					   &target->freq_req, FREQ_QOS_MAX,
					   INT_MAX);
		if (err < 0)
			goto err;
	}

	INIT_LIST_HEAD(&target->node);
	list_add(&target->node, &thr->targets);

	thr_update_throttling(thr);

	return 0;

err:
	devm_kfree(thr->dev, target->freq_table.freqs);
	devm_kfree(thr->dev, target);
	return err;
}

static void thr_remove_target(struct throttler *thr,
			      struct throttler_target *target)
{
	lockdep_assert_held(&thr->lock);

	if (target->dev)
		dev_pm_qos_remove_request(&target->dev_req);
	else
		freq_qos_remove_request(&target->freq_req);

	list_del(&target->node);
	devm_kfree(thr->dev, target->freq_table.freqs);
	devm_kfree(thr->dev, target);
}

static void thr_remove_target_by_device(struct throttler *thr,
					struct device *dev)
{
	struct throttler_target *target;

	list_for_each_entry(target, &thr->targets, node) {
		if (dev == target->dev) {
			thr_remove_target(thr, target);
			return;
		}
	}
}

static void thr_remove_target_by_policy(struct throttler *thr,
					struct cpufreq_policy *policy)
{
	struct throttler_target *target;

	list_for_each_entry(target, &thr->targets, node) {
		if (policy == target->policy) {
			thr_remove_target(thr, target);
			return;
		}
	}
}

static void thr_cpufreq_init(struct throttler *thr,
			     struct cpufreq_policy *policy)
{
	struct throttler_target *target;
	struct device *cpu_dev;
	struct thr_freq_table ft;
	int cpu = policy->cpu;
	int err;

	lockdep_assert_held(&thr->lock);

	list_for_each_entry(target, &thr->targets, node) {
		if (policy == target->policy) {
			dev_dbg(thr->dev,
				"skipping double-registered policy CPU%d\n",
				policy->cpu);
			return;
		}
	}

	cpu_dev = get_cpu_device(cpu);
	if (!cpu_dev) {
		dev_err_ratelimited(thr->dev, "failed to get CPU %d\n", cpu);
		return;
	}

	err = thr_init_freq_table(thr, cpu_dev, &ft);
	if (err) {
		/* CPU is not throttled or initialization failed */
		if (err != -ENODEV)
			dev_err(thr->dev, "failed to initialize CPU %d: %d\n",
				cpu, err);
		else
			dev_dbg(thr->dev, "failed to initialize CPU %d: %d\n",
				cpu, err);
		return;
	}

	err = thr_add_target(thr, NULL, policy, &ft);
	if (err < 0) {
		dev_err(thr->dev, "failed to add CPU%d for throttling: %d\n",
			policy->cpu, err);
		devm_kfree(thr->dev, ft.freqs);
		return;
	}

	dev_dbg(thr->dev, "CPU%d is used for throttling\n", policy->cpu);
}

static void thr_cpufreq_exit(struct throttler *thr,
			     struct cpufreq_policy *policy)
{
	thr_remove_target_by_policy(thr, policy);
}

static void thr_devfreq_init(struct device *dev, void *data)
{
	struct throttler *thr = data;
	struct thr_freq_table ft;
	int err;

	lockdep_assert_held(&thr->lock);

	err = thr_init_freq_table(thr, dev, &ft);
	if (err) {
		if (err == -ENODEV)
			return;

		dev_err(thr->dev,
			"failed to init frequency table of device %s: %d",
			dev_name(dev), err);
		return;
	}

	err = thr_add_target(thr, dev, NULL, &ft);
	if (err < 0) {
		dev_err(thr->dev,
			"failed to add device '%s' for throttling: %d\n",
			dev_name(dev), err);
		devm_kfree(thr->dev, ft.freqs);
		return;
	}

	dev_dbg(thr->dev, "device '%s' is used for throttling\n",
		dev_name(dev));
}

static void thr_devfreq_exit(struct throttler *thr,
			     struct device *dev)
{
	thr_remove_target_by_device(thr, dev);
}

static int thr_handle_devfreq_added(struct device *dev,
				    struct class_interface *ci)
{
	struct throttler *thr = ci_to_throttler(ci);

	mutex_lock(&thr->lock);
	/* devfreq uses parent for OPPs and for PM QoS. */
	thr_devfreq_init(dev->parent, thr);
	mutex_unlock(&thr->lock);

	return 0;
}

static void thr_handle_devfreq_removed(struct device *dev,
				       struct class_interface *ci)
{
	struct throttler *thr = ci_to_throttler(ci);

	mutex_lock(&thr->lock);
	thr_devfreq_exit(thr, dev);
	mutex_unlock(&thr->lock);
}

static int thr_cpufreq_notifier(struct notifier_block *nb, unsigned long event,
				void *data)
{
	struct throttler *thr = container_of(nb, struct throttler, cpufreq_nb);
	struct cpufreq_policy *policy = data;

	mutex_lock(&thr->lock);

	if (event == CPUFREQ_CREATE_POLICY)
		thr_cpufreq_init(thr, policy);
	else if (event == CPUFREQ_REMOVE_POLICY)
		thr_cpufreq_exit(thr, policy);

	mutex_unlock(&thr->lock);

	return 0;
}

void throttler_set_level(struct throttler *thr, unsigned int level)
{
	mutex_lock(&thr->lock);

	if (level == thr->level) {
		mutex_unlock(&thr->lock);
		return;
	}

	dev_dbg(thr->dev, "throttling level: %u\n", level);
	thr->level = level;

	thr_update_throttling(thr);

	mutex_unlock(&thr->lock);
}
EXPORT_SYMBOL_GPL(throttler_set_level);

static ssize_t thr_level_read(struct file *file, char __user *user_buf,
			      size_t count, loff_t *ppos)
{
	struct throttler *thr = file->f_inode->i_private;
	char buf[5];
	int len;

	len = scnprintf(buf, sizeof(buf), "%u\n", READ_ONCE(thr->level));

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t thr_level_write(struct file *file, const char __user *user_buf,
			       size_t count, loff_t *ppos)
{
	int rc;
	unsigned int level;
	struct throttler *thr = file->f_inode->i_private;

	rc = kstrtouint_from_user(user_buf, count, 10, &level);
	if (rc)
		return rc;

	throttler_set_level(thr, level);

	return count;
}

static const struct file_operations level_debugfs_ops = {
	.owner = THIS_MODULE,
	.read = thr_level_read,
	.write = thr_level_write,
};

struct throttler *throttler_setup(struct device *dev)
{
	struct throttler *thr;
	struct device_node *np = dev->of_node;
	struct class_interface *ci;
	struct dentry *attr_level;
	int cpu;
	int err;

	if (!np)
		/* should never happen */
		return ERR_PTR(-EINVAL);

	thr = devm_kzalloc(dev, sizeof(*thr), GFP_KERNEL);
	if (!thr)
		return ERR_PTR(-ENOMEM);

	mutex_init(&thr->lock);
	thr->dev = dev;

	INIT_LIST_HEAD(&thr->targets);

	thr->cpufreq_nb.notifier_call = thr_cpufreq_notifier;
	err = cpufreq_register_notifier(&thr->cpufreq_nb,
					CPUFREQ_POLICY_NOTIFIER);
	if (err) {
		dev_err(thr->dev, "failed to register cpufreq notifier: %d\n",
			err);
		return ERR_PTR(err);
	}

	mutex_lock(&thr->lock);
	for_each_possible_cpu(cpu) {
		struct cpufreq_policy *policy = cpufreq_cpu_get(cpu);

		if (!policy)
			continue;

		thr_cpufreq_init(thr, policy);
		cpufreq_cpu_put(policy);
	}
	mutex_unlock(&thr->lock);

	/*
	 * devfreq devices can be added and removed at runtime, hence they
	 * must be handled dynamically. The class_interface notifies us
	 * whenever a device is added or removed. When the interface is
	 * registered ci->add_dev() is called for all existing devfreq
	 * devices.
	 */
	ci = &thr->devfreq_class_iface;
	ci->class = devfreq_class;
	ci->add_dev = thr_handle_devfreq_added;
	ci->remove_dev = thr_handle_devfreq_removed;

	err = class_interface_register(ci);
	if (err) {
		dev_err(thr->dev,
			"failed to register devfreq class interface: %d\n",
			err);
		goto unregister_cpufreq;
	}

	thr->debugfs_dir = debugfs_create_dir(dev_name(thr->dev), NULL);
	if (IS_ERR(thr->debugfs_dir)) {
		dev_dbg(thr->dev, "failed to create debugfs directory: %ld\n",
			PTR_ERR(thr->debugfs_dir));
		thr->debugfs_dir = NULL;
	} else {
		attr_level =
			debugfs_create_file("level", 0644, thr->debugfs_dir,
					    thr, &level_debugfs_ops);
		if (IS_ERR(attr_level)) {
			dev_warn(thr->dev,
				 "failed to create debugfs attribute: %ld\n",
				 PTR_ERR(attr_level));
			debugfs_remove(thr->debugfs_dir);
			thr->debugfs_dir = NULL;
		}
	}

	return thr;

unregister_cpufreq:
	cpufreq_unregister_notifier(&thr->cpufreq_nb, CPUFREQ_POLICY_NOTIFIER);

	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(throttler_setup);

void throttler_teardown(struct throttler *thr)
{
	struct throttler_target *target, *tmp;

	debugfs_remove_recursive(thr->debugfs_dir);

	class_interface_unregister(&thr->devfreq_class_iface);
	cpufreq_unregister_notifier(&thr->cpufreq_nb, CPUFREQ_POLICY_NOTIFIER);

	mutex_lock(&thr->lock);

	list_for_each_entry_safe(target, tmp, &thr->targets, node)
		thr_remove_target(thr, target);

	mutex_unlock(&thr->lock);
}
EXPORT_SYMBOL_GPL(throttler_teardown);
