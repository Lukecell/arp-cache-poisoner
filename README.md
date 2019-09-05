# arp-cache-poisoner
A Man In The Middle tool using arp cache poisoning, written entirely in C via raw sockets, currently only works for GNU/Linux.

Currently, the only working part is that it reads and displays packet information, and blocks traffic for the victim

In order to compile, run `make INSTALL`, and go into bin and run the binary
