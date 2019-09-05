/*#include <sys/socket.h>
#include <sys/ioctl.h>
#include <asm/types.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>*/
#include "getif.h"

/*
 * Converts struct sockaddr with an IPv4 address to network byte order uin32_t.
 * Returns 0 on success.
*/
int int_ip4(struct sockaddr *addr, uint32_t *ip)
{
	if (addr->sa_family == AF_INET) {
		struct sockaddr_in *i = (struct sockaddr_in *) addr;
 		*ip = i->sin_addr.s_addr;
		return 0;
	} else {
		printf("\nNot AF_INET");
		return 1;
	}
}

/*
 * Writes interface IPv4 address as network byte order to ip.
 * Returns 0 on success.
*/
int get_if_ip4(int fd, const char *ifname, uint32_t *ip) {
	int err = -1;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
	if (strlen(ifname) > (IFNAMSIZ - 1)) {
		printf("\nToo long interface name");
		goto out;
	}
 
	strcpy(ifr.ifr_name, ifname);
	if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
		printf("\nSIOCGIFADDR");
		goto out;
	}

	if (int_ip4(&ifr.ifr_addr, ip)) {
		goto out;
	}
	err = 0;
	out:
		return err;
}

/*
 * Gets interface information by name:
 * IPv4
 * MAC
 * ifindex
*/
int get_if_info(const char *ifname, uint32_t *ip, char *mac, int *ifindex)
{
	printf("\nget_if_info for %s", ifname);
	int err = -1;
	struct ifreq ifr;
	int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sd <= 0) {
		perror("socket()");
		goto out;
	}
	if (strlen(ifname) > (IFNAMSIZ - 1)) {
		printf("Too long interface name, MAX=%i\n", IFNAMSIZ - 1);
		goto out;
	}

	strcpy(ifr.ifr_name, ifname);

	//Get interface index using name
	if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
		printf("\nSIOCGIFINDEX");
		goto out;
	}
	*ifindex = ifr.ifr_ifindex;
	printf("interface index is %d\n", *ifindex);

	//Get MAC address of the interface
	if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
		printf("\nSIOCGIFINDEX");
		goto out;
	}

	//Copy mac address to output
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6); /*MAC_LENGTH */

	if (get_if_ip4(sd, ifname, ip)) {
		goto out;
	}
	printf("\nget_if_info OK");

	err = 0;
	out:
		if (sd > 0) {
			printf("\nClean up temporary socket");
			close(sd);
		}
	return err;
}
