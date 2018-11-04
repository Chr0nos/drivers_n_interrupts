# Drivers and Interrupts
### About the project
This is a 42 school project, the purpose is to make a linux kernel keylogger.

It uses interrupts and shared IRQ to spy the keyboard input, the logs are
available into /dev/keylogger (for root only).

### Dependencies
make, linux headers (i do my tests on an archlinux 4.19), gcc