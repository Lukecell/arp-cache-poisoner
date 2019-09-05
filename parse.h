#ifndef PARSE_H_
#define PARSE_H_

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

#define ETH2_HEADER_LEN 14
#define HW_TYPE         1
#define MAC_LENGTH      6
#define IPV4_LENGTH     4
#define ARP_REQUEST     0x01
#define ARP_REPLY       0x02

int parse_udp(unsigned char buffer[], struct ethhdr *recv_resp, struct iphdr *ip_resp);
int parse_tcp(unsigned char buffer[], struct ethhdr *recv_resp, struct iphdr *ip_resp);
int parse_arp(unsigned char buffer[], struct ethhdr *recv_resp);
int parse_ip(unsigned char buffer[], struct ethhdr *recv_resp);

#endif
