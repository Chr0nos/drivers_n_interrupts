# Drivers and Interrupts
### About the project
This is a 42 school project, the purpose is to make a linux kernel keylogger.

It uses interrupts and shared IRQ to spy the keyboard input, the logs are
available into /dev/keylogger (for root only).

Stats are availables at /dev/keylog_stats, and a user friendly line can be read at /dev/keylog_line.

You can find the subject at https://cdn.intra.42.fr/pdf/pdf/773/lk_driver_and_keyboard.en.pdf

### Dependencies
make, linux headers (i do my tests on an archlinux 4.19), gcc
