#define ETH2_HEADER_LEN 14
#define HW_TYPE         1
#define MAC_LENGTH      6
#define IPV4_LENGTH     4
#define ARP_REQUEST     0x01
#define ARP_REPLY       0x02
#define BUF_SIZE        60

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


#define debug(x...) printf(x);printf("\n");
#define info(x...)  printf(x);printf("\n");
#define warn(x...)  printf(x);printf("\n");
#define err(x...)   printf(x);printf("\n");

/**/

int parse_arp(unsigned char buffer[BUF_SIZE], struct ethhdr *recv_resp);
int parse_ip(unsigned char buffer[BUF_SIZE], struct ethhdr *recv_resp);
int parse_tcp(unsigned char buffer[BUF_SIZE], struct ethhdr *recv_resp, struct iphdr *ip_resp);
int parse_udp(unsigned char buffer[BUF_SIZE], struct ethhdr *recv_resp, struct iphdr *ip_resp);

/*
 * Sends an ARP who-has request to dst_ip
 * on interface ifindex, using source mac src_mac and source ip src_ip.
 */
int send_arp(int fd, int ifindex, const unsigned char *src_mac, uint32_t src_ip, uint32_t dst_ip)
{
	int err = -1;
	unsigned char buffer[BUF_SIZE];
	memset(buffer, 0, sizeof(buffer));

	struct sockaddr_ll socket_address;
	socket_address.sll_family = AF_PACKET;
	socket_address.sll_protocol = htons(ETH_P_ARP);
	socket_address.sll_ifindex = ifindex;
	socket_address.sll_hatype = htons(ARPHRD_ETHER);
	socket_address.sll_pkttype = (PACKET_BROADCAST);
	socket_address.sll_halen = MAC_LENGTH;
	socket_address.sll_addr[6] = 0x00;
	socket_address.sll_addr[7] = 0x00;

	struct ethhdr *send_req = (struct ethhdr *) buffer;
	struct arp_header *arp_req = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
	ssize_t ret;

	//Broadcast
	memset(send_req->h_dest, 0xff, MAC_LENGTH);

	//Target MAC zero
	memset(arp_req->target_mac, 0x00, MAC_LENGTH);

	//Set source mac to our MAC address
	memcpy(send_req->h_source, src_mac, MAC_LENGTH);
	memcpy(arp_req->sender_mac, src_mac, MAC_LENGTH);
	memcpy(socket_address.sll_addr, src_mac, MAC_LENGTH);

	/* Setting protocol of the packet */
	send_req->h_proto = htons(ETH_P_ARP);

	/* Creating ARP request */
	arp_req->hardware_type = htons(HW_TYPE);
	arp_req->protocol_type = htons(ETH_P_IP);
	arp_req->hardware_len = MAC_LENGTH;
	arp_req->protocol_len = IPV4_LENGTH;
	arp_req->opcode = htons(ARP_REPLY);

	debug("Copy IP address to arp_req");
	memcpy(arp_req->sender_ip, &dst_ip, sizeof(uint32_t));
	memcpy(arp_req->target_ip, &src_ip, sizeof(uint32_t));

	ret = sendto(fd, buffer, 42, 0, (struct sockaddr *) &socket_address, sizeof(socket_address));
	if (ret == -1) {
		perror("sendto():");
		goto out;
	}
	err = 0;
out:
	return err;
}

int bind_all(int ifindex, int *fd){
	int ret = -1;
	*fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (*fd < 1) {
		perror("socket()");
		goto out;
	}

	debug("Binding to ifindex %d", ifindex);
	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof(struct sockaddr_ll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = ifindex;
	if (bind(*fd, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0) {
		perror("bind");
		goto out;
	}

	ret = 0;

out:
	if (ret && *fd > 0) {
		debug("Cleanup socket");
		close(*fd);
	}
	return ret;
}

int read_all(int fd){
	//debug("read_all");
	int ret = -1;
	unsigned char buffer[BUF_SIZE];
	ssize_t length = recvfrom(fd, buffer, BUF_SIZE, 0, NULL, NULL);
	if (length == -1) {
	perror("recvfrom()");
		return ret;
	}
	struct ethhdr *rcv_resp = (struct ethhdr *) buffer;

/*	printf("\nProtocol: %hu\n", rcv_resp->h_proto);*/

	if(ntohs(rcv_resp->h_proto) == 2054)
	{
		printf("\nARP: ");
		//printf("\nPROTO_ARP\n");
		return parse_arp(buffer, rcv_resp);
	}
	else if(ntohs(rcv_resp->h_proto) == 2048)
	{
		printf("\n\nIP: ");
		return parse_ip (buffer, rcv_resp);
	}

	return 0;
}

int test_arping(const char *ifname, const char *ip) {
	int ret = -1;
	uint32_t dst = inet_addr(ip);
	if (dst == 0 || dst == 0xffffffff) {
		printf("Invalid source IP\n");
		return 1;
	}

	int src;
	int ifindex;
	char mac[MAC_LENGTH];
	if (get_if_info(ifname, &src, mac, &ifindex)) {
		err("get_if_info failed, interface %s not found or no IP set?", ifname);
		return ret;
	}
	int fd;

	if (bind_all(ifindex, &fd))
	{
		err("Failed to bind ip()");
		return ret;
	}

	//if (send_arp(arp_fd, ifindex, mac, src, dst)) {
	//    err("Failed to send_arp");
	//    goto out;
	//}

	while(1) {
		read_all(fd);
	}

	ret = 0;
/*out:*/
/*	if (arp_fd) {*/
/*		close(arp_fd);*/
/*		arp_fd = 0;*/
/*	}*/
	return ret;
}

int main(int argc, const char **argv) {
	if (argc != 3) {
		printf("Usage: %s <INTERFACE> <DEST_IP>\n", argv[0]);
		return 1;
	}
	const char *ifname = argv[1];
	const char *ip = argv[2];
	return test_arping(ifname, ip);
}
