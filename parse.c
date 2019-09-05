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
#include <linux/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>  //htons etc
#include "getif.h"
#include "parse.h"

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


#define PROTO_ARP 0x0806 //Ethernet protocol number
#define PROTO_IP  0x0800 //Ethernet protocol number

#define PROTO_TCP 0x06   //Internet Protocol number
#define PROTO_UDP 0x11   //Internet Protocol number

#define BUF_SIZE        60

int parse_arp(unsigned char buffer[BUF_SIZE], struct ethhdr *recv_resp)
{
	printf("\nparse_arp");

	struct arp_header *arp_resp = (struct arp_header *) (buffer + ETH2_HEADER_LEN);	

	struct in_addr sender_a;
	memset(&sender_a, 0, sizeof(struct in_addr));
	memcpy(&sender_a.s_addr, arp_resp->sender_ip, sizeof(uint32_t));

	int i = 0;
	struct in_addr target_a;
	memset(&target_a, 0, sizeof(struct in_addr));
	memcpy(&target_a.s_addr, arp_resp->target_ip, sizeof(uint32_t));

	printf("\nTarget IP: %s", inet_ntoa(target_a));
	printf("\n");
	//debug("Target IP Length: %d", target_ip_len);
	printf("\nSender IP: %s", inet_ntoa(sender_a));

	printf("\nSender MAC: %02X:%02X:%02X:%02X:%02X:%02X",
		arp_resp->sender_mac[0],
		arp_resp->sender_mac[1],
		arp_resp->sender_mac[2],
		arp_resp->sender_mac[3],
		arp_resp->sender_mac[4],
		arp_resp->sender_mac[5]);
}

int parse_tcp(unsigned char buffer[BUF_SIZE], struct ethhdr *recv_resp, struct iphdr *ip_resp)
{
	struct tcphdr *tcp_resp = (struct tcphdr *) (buffer + sizeof(struct ethhdr) + sizeof(struct tcphdr));

	printf("\nSource Port: %hu", ntohs(tcp_resp->source));
	printf("\nDestination Port: %hu\n", ntohs(tcp_resp->dest));

	//printf("\nSource Port: %d\nDestination Port: %d\n\n", );
}

int parse_udp(unsigned char buffer[BUF_SIZE], struct ethhdr *recv_resp, struct iphdr *ip_resp)
{
	struct udphdr *udp_resp = (struct udphdr *) (buffer + sizeof(struct ethhdr) + sizeof(struct tcphdr));

	printf("\nSource Port: %hu", ntohs(udp_resp->source));
	printf("\nDestination Port: %hu\n\n", ntohs(udp_resp->dest));
}

int parse_ip(unsigned char buffer[BUF_SIZE], struct ethhdr *recv_resp)
{
	//debug("parse_ip");

	struct iphdr *ip_resp = (struct iphdr *) (buffer + sizeof(struct ethhdr));

	if(ip_resp->protocol == PROTO_TCP)
	{
		return 0; //parse_tcp(buffer, recv_resp, ip_resp);
	}

	struct sockaddr_in source;
	struct sockaddr_in dest;

	source.sin_addr.s_addr=ip_resp->saddr; //Place the IP addresses in a struct
	dest.sin_addr.s_addr  =ip_resp->daddr; //that can be read by inet_ntoa

//	debug("ASD\n");

	printf("Source IP`: %s\nDestination IP: %s", 
			inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr));	

	if(ip_resp->protocol == PROTO_TCP)
	{
		//parse_tcp(buffer, recv_resp, ip_resp);
	}
	else if(ip_resp->protocol == PROTO_UDP)
	{
		parse_udp(buffer, recv_resp, ip_resp);
	}
}
