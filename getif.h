#ifndef GETIF_H_   /* Include guard */
#define GETIF_H_

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <asm/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>  //htons etc

int int_ip4(struct sockaddr *addr, uint32_t *ip);
int get_if_ip4(int fd, const char *ifname, uint32_t *ip);
int get_if_info(const char *ifname, uint32_t *ip, char *mac, int *ifindex);


#endif // FOO_H_
