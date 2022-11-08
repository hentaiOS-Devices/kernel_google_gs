/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_THROTTLER_H__
#define __LINUX_THROTTLER_H__

struct throttler;

extern struct throttler *throttler_setup(struct device *dev);
extern void throttler_teardown(struct throttler *thr);
extern void throttler_set_level(struct throttler *thr, unsigned int level);

#endif /* __LINUX_THROTTLER_H__ */
