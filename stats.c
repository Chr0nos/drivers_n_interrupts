// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/miscdevice.h>
#include "keylog.h"

/* ------------------------ KEY STATS DEVICE -------------------------------- */

static size_t		key_total_presss(void)
{
	size_t		i;
	size_t		count;

	count = 0;
	for (i = 0; key_table[i].name; i++)
		count += key_table[i].press_count;
	return count;
}

static int		key_stats_show(struct seq_file *seq, void *ptr)
{
	const struct key_map	*key;
	const size_t		total_press = key_total_presss();
	float			pct;
	size_t			j;

	key = &key_table[0];
	while (key->name) {
		for (j = 0; j < 4; j++) {
			key++;
			if (!key->name)
				break;
			pct = (float)key->press_count / total_press;
			seq_printf(seq, "%s %3ld", key->name, key->press_count);
		}
		seq_putc(seq, '\n');
	}
	return 0;
}

static int		stats_open(struct inode *node, struct file *file)
{
	int		ret;

	spin_lock(&slock);
	ret = single_open(file, key_stats_show, NULL);
	spin_unlock(&slock);
	return ret;
}

static const struct file_operations ops = {
	.owner = THIS_MODULE,
	.open = stats_open,
	.read = seq_read,
	.release = single_release,
	.llseek = seq_lseek
};

static struct miscdevice		dev = {
	MISC_DYNAMIC_MINOR,
	"keylog_stats",
	&ops
};

int		stats_init(void)
{
	return misc_register(&dev);
}
void		stats_exit(void)
{
	misc_deregister(&dev);
}