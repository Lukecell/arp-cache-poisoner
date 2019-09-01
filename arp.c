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

#define PROTO_ARP 0x0806 //Ethernet protocol number
#define PROTO_IP  0x0800 //Ethernet protocol number

#define PROTO_TCP 0x06   //Internet Protocol number
#define PROTO_UDP 0x11   //Internet Protocol number

#define ETH2_HEADER_LEN 14
#define HW_TYPE         1
#define MAC_LENGTH      6
#define IPV4_LENGTH     4
#define ARP_REQUEST     0x01
#define ARP_REPLY       0x02
#define BUF_SIZE        60

#define debug(x...) printf(x);printf("\n");
#define info(x...)  printf(x);printf("\n");
#define warn(x...)  printf(x);printf("\n");
#define err(x...)   printf(x);printf("\n");

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

int parse_arp(unsigned char buffer[BUF_SIZE], struct ethhdr *recv_resp);
int parse_ip(unsigned char buffer[BUF_SIZE], struct ethhdr *recv_resp);
int parse_tcp(unsigned char buffer[BUF_SIZE], struct ethhdr *recv_resp, struct iphdr *ip_resp);
int parse_udp(unsigned char buffer[BUF_SIZE], struct ethhdr *recv_resp, struct iphdr *ip_resp);


/*struct ether_header {
    uint8_t  dst_addr[6];
    uint8_t  src_addr[6];
    uint16_t llc_len;
};*/

/*typedef struct {
    uint8_t  ver_ihl;  // 4 bits version and 4 bits internet header length
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
	uint16_t flags_fo; // 3 bits flags and 13 bits fragment-offset
	uint8_t  ttl;
	uint8_t  protocol;
	uint16_t checksum;
	addr_t   src_addr;
	addr_t   dst_addr;
} ip_header_t;*/

/*
 * Converts struct sockaddr with an IPv4 address to network byte order uin32_t.

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
        err("Not AF_INET");
        return 1;
    }
}

/*
 * Formats sockaddr containing IPv4 address as human readable string.
 * Returns 0 on success.
 */
int format_ip4(struct sockaddr *addr, char *out)
{
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *i = (struct sockaddr_in *) addr;
        const char *ip = inet_ntoa(i->sin_addr);
        if (!ip) {
            return -2;
        } else {
            strcpy(out, ip);
            return 0;
        }
    } else {
        return -1;
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
        err("Too long interface name");
        goto out;
    }

    strcpy(ifr.ifr_name, ifname);
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("SIOCGIFADDR");
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
    int index;
    ssize_t ret, length = 0;

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

/*
 * Gets interface information by name:
 * IPv4
 * MAC
 * ifindex
 */
int get_if_info(const char *ifname, uint32_t *ip, char *mac, int *ifindex)
{
    debug("get_if_info for %s", ifname);
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
        perror("SIOCGIFINDEX");
        goto out;
    }
    *ifindex = ifr.ifr_ifindex;
    printf("interface index is %d\n", *ifindex);

    //Get MAC address of the interface
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        goto out;
    }

    //Copy mac address to output
    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);

    if (get_if_ip4(sd, ifname, ip)) {
        goto out;
    }
    debug("get_if_info OK");

    err = 0;
out:
    if (sd > 0) {
        debug("Clean up temporary socket");
        close(sd);
    }
    return err;
}

/*
 * Creates a raw socket that listens for ARP traffic on specific ifindex.
 * Writes out the socket's FD.
 * Return 0 on success.
 */
int bind_arp(int ifindex, int *fd)
{
    debug("bind_arp: ifindex=%i", ifindex);
    int ret = -1;

    // Submit request for a raw socket descriptor.
    *fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (*fd < 1) {
        perror("socket()");
        goto out;
    }

    debug("Binding to ifindex %i", ifindex);
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
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

int bind_ip(int ifindex, int *fd)
{
    debug("bind_ip: ifindex=%i", ifindex);
    int ret = -1;

    // Submit request for a raw socket descriptor.
    *fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (*fd < 1) {
        perror("socket()");
        goto out;
    }

    debug("Binding to ifindex %i", ifindex);
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
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
	int index;
	if (length == -1) {
	perror("recvfrom()");
		return ret;
	}
	struct ethhdr *rcv_resp = (struct ethhdr *) buffer;

/*	printf("\nProtocol: %hu\n", rcv_resp->h_proto);*/

	if(rcv_resp->h_proto == 1544)
	{
		printf("\nARP: ");
		//printf("\nPROTO_ARP\n");
		return parse_arp(buffer, rcv_resp);
	}
	else if(rcv_resp->h_proto == 8)
	{
		printf("\nIP: ");
		return parse_ip (buffer, rcv_resp);
	}
}

int parse_arp(unsigned char buffer[BUF_SIZE], struct ethhdr *recv_resp)
{
	debug("parse_arp");

	printf("%d", recv_resp->h_proto);

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
	debug("Sender IP: %s", inet_ntoa(sender_a));

	debug("Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X",
		arp_resp->sender_mac[0],
		arp_resp->sender_mac[1],
		arp_resp->sender_mac[2],
		arp_resp->sender_mac[3],
		arp_resp->sender_mac[4],
		arp_resp->sender_mac[5]);
}

int parse_ip(unsigned char buffer[BUF_SIZE], struct ethhdr *recv_resp)
{
	debug("parse_ip");

	struct iphdr *ip_resp = (struct iphdr *) (buffer + sizeof(struct ethhdr));

	struct sockaddr_in source;
	struct sockaddr_in dest;

	source.sin_addr.s_addr=ip_resp->saddr; //Place the IP addresses in a struct
	dest.sin_addr.s_addr  =ip_resp->daddr; //that can be read by inet_ntoa

//	debug("ASD\n");

	printf("Source IP`: %s\nDestination IP: %s", 
			inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr));	

	if(ip_resp->protocol == PROTO_TCP)
	{
		parse_tcp(buffer, recv_resp, ip_resp);
	}
	else if(ip_resp->protocol == PROTO_UDP)
	{
		parse_tcp(buffer, recv_resp, ip_resp);
	}
}

int parse_tcp(unsigned char buffer[BUF_SIZE], struct ethhdr *recv_resp, struct iphdr *ip_resp)
{
	debug("parse_tcp");
}

int parse_udp(unsigned char buffer[BUF_SIZE], struct ethhdr *recv_resp, struct iphdr *ip_resp)
{
	debug("parse_udp");
}

/*
 * Reads a single ARP reply from fd.
 * Return 0 on success.
 */

/*int read_arp(int fd, unsigned char target_ip[]*//*, int target_ip_len)*/
/*{
	debug("read_arp");
	int ret = -1;
    unsigned char buffer[BUF_SIZE];
    ssize_t length = recvfrom(fd, buffer, BUF_SIZE, 0, NULL, NULL);
    int index;
    if (length == -1) {
        perror("recvfrom()");
        goto out;
    }
    struct ethhdr *rcv_resp = (struct ethhdr *) buffer;
    struct arp_header *arp_resp = (struct arp_header *) (buffer + ETH2_HEADER_LEN);

    if (ntohs(arp_resp->opcode) != ARP_REQUEST) {
        debug("Not an ARP reply");
        goto out;
    }
    debug("received ARP len=%ld", length);
    struct in_addr sender_a;
    memset(&sender_a, 0, sizeof(struct in_addr));
    memcpy(&sender_a.s_addr, arp_resp->sender_ip, sizeof(uint32_t));

    int i = 0;
    struct in_addr target_a;
    memset(&target_a, 0, sizeof(struct in_addr));
    memcpy(&target_a.s_addr, arp_resp->target_ip, sizeof(uint32_t));

    struct in_addr target_b;
    memset(&target_b, 0, sizeof(struct in_addr));
    memcpy(&target_b.s_addr, target_ip, sizeof(uint32_t));


    printf("\nTarget IP: %s", inet_ntoa(target_a));
    printf("\n");
    debug("Our IP: %s", target_ip);
    //debug("Target IP Length: %d", target_ip_len);
    debug("Sender IP: %s", inet_ntoa(sender_a));

    debug("Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X",
          arp_resp->sender_mac[0],
          arp_resp->sender_mac[1],
          arp_resp->sender_mac[2],
          arp_resp->sender_mac[3],
          arp_resp->sender_mac[4],
          arp_resp->sender_mac[5]);

    ret = 0;

    for(i = 0; i < strlen(inet_ntoa(target_a)); i++)
    {
        if(target_ip[i] == inet_ntoa(target_a)[i])
            printf("\n%d", i);
        else
            return -1;
    }

    return 1;

    //return strcmp(target_ip, inet_ntoa(target_a));

out:
    return ret;
}

void print_ip(unsigned int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);
}*/

/*
 * Reads a single IP reply from fd.
 * Return 0 on success.
 */
/*int read_ip(int fd)
{
	debug("read_ip\n");
	int ret = -1;
    unsigned char buffer[BUF_SIZE];
    ssize_t length = recvfrom(fd, buffer, BUF_SIZE, 0, NULL, NULL);
    int index;
    if (length == -1) {
        perror("recvfrom()");
        return ret;
    }
    struct ethhdr *rcv_resp = (struct ethhdr *) buffer;
    struct iphdr *ip_resp = (struct iphdr *) (buffer + sizeof(struct ethhdr));

	struct sockaddr_in source;
	struct sockaddr_in dest;

	source.sin_addr.s_addr=ip_resp->saddr;
	dest.sin_addr.s_addr  =ip_resp->daddr;

//	debug("ASD\n");

	printf("Source IP Address: %s\nDestination IP Address", inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr));

//	debug("\nDAS\n");
	if(ip_resp -> protocol == PROTO_TCP)
	{
		struct tcphdr *tcp_resp = (struct tcphdr *) (buffer + sizeof(rcv_resp) + ip_resp->ihl);
		//debug("tcp source port: %u", tcp_resp->th_sport);
		//debug("tcp destination port: %u", tcp_resp->th_dport);
	}
}*/
/*
 *
 * Sample code that sends an ARP who-has request on
 * interface <ifname> to IPv4 address <ip>.
 * Returns 0 on success.
 */
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
        goto out;
    }
    int arp_fd;
	int ip_fd;
	int fd;
    if (bind_arp(ifindex, &arp_fd)) {
        err("Failed to bind_arp()");
        goto out;
    }
	if (bind_ip(ifindex, &ip_fd))
	{
		err("Failed to bind ip()");
		goto out;
	}

	if (bind_all(ifindex, &fd))
	{
		err("Failed to bind ip()");
		goto out;
	}

    //if (send_arp(arp_fd, ifindex, mac, src, dst)) {
    //    err("Failed to send_arp");
    //    goto out;
    //}

/*    unsigned char *ipCast = ip;*/

    while(1) {
		sleep(10);
        //int s = send_arp(arp_fd, ifindex, mac, src, dst); 
        //sleep(2);
        //int r = read_arp(arp_fd, ipCast/*, ipCast, sizeof(ipCast)*/);
		int d = read_all(fd);

        /*if(r == 1)
            send_arp(arp_fd, ifindex, mac, src, dst);//if(r != -1)*/
            send_arp(arp_fd, ifindex, mac, src, dst);
        //sleep(2);
    }

    ret = 0;
out:
    if (arp_fd) {
        close(arp_fd);
        arp_fd = 0;
    }
    return ret;
}

int main(int argc, const char **argv) {
    int ret = -1;
	sleep(3);
    if (argc != 3) {
        printf("Usage: %s <INTERFACE> <DEST_IP>\n", argv[0]);
        return 1;
    }
    const char *ifname = argv[1];
    const char *ip = argv[2];
    return test_arping(ifname, ip);
}