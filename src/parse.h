#ifndef PARSE_H_
#define PARSE_H_

struct output {
	unsigned short port;
	unsigned int   s_addr;
};

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

struct arp_header {
	unsigned short hardware_type;
	unsigned short protocol_type;
	unsigned char  hardware_len;
	unsigned char  protocol_len;
	unsigned short opcode;
	unsigned char  sender_mac[MAC_LENGTH];
	unsigned char  sender_ip[IPV4_LENGTH];
	unsigned char  target_mac[MAC_LENGTH];
	unsigned char  target_ip[IPV4_LENGTH];
};

unsigned short parse_udp(unsigned char buffer[], struct ethhdr *recv_resp, struct iphdr *ip_resp);
unsigned short parse_tcp(unsigned char buffer[], struct ethhdr *recv_resp, struct iphdr *ip_resp);
int parse_arp(unsigned char buffer[], struct ethhdr *recv_resp);
struct sockaddr_in parse_ip(unsigned char buffer[], struct ethhdr *recv_resp);

#endif
