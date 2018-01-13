#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <libgen.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>
#include <linux/icmp.h>

#include "types.h"
#include "utils.h"



/* 	RFC 791 ip protocol: https://tools.ietf.org/html/rfc791#page-11
	RFC 793 tcp protocol: https://tools.ietf.org/html/rfc793#page-15
	RFC 768 udp protocol: https://tools.ietf.org/html/rfc768 */


/*	© Copyright 2017-2018 Manu-sh s3gmentationfault@gmail.com
	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
       	the Free Software Foundation, either version 3 of the License.
	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
	See the GNU General Public License for more details.
	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>. */


int32_t socket_raw = -1;

/* these header have a fixed size */
const uint16_t ethhdrlen = sizeof(struct ethhdr);

static void close_rawsk()
{ if (socket_raw != -1) close(socket_raw); }

/* TODO should i reset the original setting before exit() */
static bool setpromisc(struct ifreq *ifr, const char *ifname, int32_t socket) {

	memset(ifr, 0, sizeof(struct ifreq));
	strcpy(ifr->ifr_name, ifname);

	/* SIOCGIFFLAGS => GET */
	if ((ioctl(socket, SIOCGIFFLAGS, ifr)) == -1)
		return false;

	/* SIOCSIFFLAGS => SET */
	ifr->ifr_flags |= IFF_PROMISC;
	if ((ioctl(socket, SIOCSIFFLAGS, ifr)) == -1)
		return false;

	return ifr->ifr_flags & IFF_PROMISC;
}



static bool packet_init(const char *buf, YasuIpv4 *p, int32_t readed) {

	struct ethhdr *ethframe = (struct ethhdr *)buf;
	struct iphdr *ip = (struct iphdr *)(buf + ethhdrlen); /* skip ethframe */

	/* according to rfc791:

		Version:  4 bits
		The Version field indicates the format of the internet header. 
	*/

	/* since ip->version is defined as 4 bit (less than one single byte)
	using bit-field there aren't problems of endianness and we can store directly */

	if (ip->version != 4) /* discard any other things */
		return false;

	/* according to wikipedia:

		The Internet Header Length (IHL) field has 4 bits, which is the number of 32-bit words.
		Since an IPv4 header may contain a variable number of options, this field specifies the size of the header
		(this also coincides with the offset to the data).
		
		The minimum value for this field is 5, which indicates a length of 5 × 32 bits = 160 bits = 20 bytes. As a 4-bit field,
		the maximum value is 15 words (15 × 32 bits, or 480 bits = 60 bytes).

	  according to rfc791:

		https://tools.ietf.org/html/rfc791
		IHL: 4 bits
		Internet Header Length is the length of the internet header in 32
		bit words, and thus points to the beginning of the data. Note that
		the minimum value for a correct header is 5.
	*/

	/*  ip->ihl 4 bit */
	p->ip_hdrlen = (uint16_t)DWORD2BYTE(ip->ihl);  
	
	/* ATTENTION we use these value as an index but they are size so attention to don't exceed ETHER_MAX_LEN
	the size of buffer */

	assert(p->ip_hdrlen < (ETHER_MAX_LEN - ethhdrlen));

	if (p->ip_hdrlen < DWORD2BYTE(5) || p->ip_hdrlen > DWORD2BYTE(15)) /* discard */
		return false;


	snprintf(p->mac_src, MAC_ADDRSTRLEN, "%02x:%02x:%02x:%02x:%02x:%02x",
		ethframe->h_source[0],
		ethframe->h_source[1],
		ethframe->h_source[2],
		ethframe->h_source[3],
		ethframe->h_source[4],
		ethframe->h_source[5]);

	snprintf(p->mac_dst, MAC_ADDRSTRLEN, "%02x:%02x:%02x:%02x:%02x:%02x",
		ethframe->h_dest[0],
		ethframe->h_dest[1],
		ethframe->h_dest[2],
		ethframe->h_dest[3],
		ethframe->h_dest[4],
		ethframe->h_dest[5]);

	/* according to IANA, see also /etc/protocol, protocol have a numer for identify it,
	for example the IANA protocol number for tcp is 6 (IPPROTO_TCP)
	these symbolic constants are defined into netinet/in.h,
	if the ip payload is a tcp packet, then ip->protocol == IPPROTO_TCP
	So getprotobynumber() just resolve the number of the protocol into his name. */

	/* get info on which type of packet ip transport */
	p->protocol  = getprotobynumber(ip->protocol);  /* since ip->protocol is a single byte there aren't problems with endianness */

	{
		struct in_addr source, dest;
		source.s_addr = ip->saddr;
		dest.s_addr   = ip->daddr;

		strncpy(p->ip_src, inet_ntoa(source), INET_ADDRSTRLEN);
		strncpy(p->ip_dst, inet_ntoa(dest), INET_ADDRSTRLEN);
	}

	switch (ip->protocol) {

		/* TCP_PACKET = ETH_FRAME + IP_HDR + TCP_HDR + DATA */

		case IPPROTO_TCP:
			{
				/* according to wikipedia:

					Specifies the size of the TCP header in 32-bit words.
					The minimum size header is 5 words and the maximum is 15 words thus giving 
					the minimum size of 20 bytes and maximum of 60 bytes, allowing for up
					to 40 bytes of options in the header.

					This field gets its name from the fact that it is also the offset from the start of the 
					TCP segment to the actual data.

					https://tools.ietf.org/html/rfc793
					Data Offset: 4 bits
					The number of 32 bit words in the TCP Header. This indicates the data begins.
					The TCP header (even one including options) is an integral number of 32 bits long.
				*/

				struct tcphdr *tcp = (struct tcphdr *)(buf + ethhdrlen + p->ip_hdrlen); /* skip eth and ip frame */
				p->t_hdrlen = (uint16_t)DWORD2BYTE(tcp->doff); /* 4 bit we can store directly */

				/* ATTENTION we use these value as an index but they are size so attention to don't exceed ETHER_MAX_LEN
				the size of buffer */

				assert((readed - ethhdrlen - p->ip_hdrlen) < ETHER_MAX_LEN);

				// TODO check for malformed DOFF

				if (p->t_hdrlen < DWORD2BYTE(5) || p->t_hdrlen > DWORD2BYTE(15))
					return false;

				p->port_dst = ntohs(tcp->dest);
				p->port_src = ntohs(tcp->source);
			}
			break;
		case IPPROTO_UDP:

			return false; /* discard for now */

			/*
			{
				struct udphdr *udp = (struct udphdr *)(buf + ethhdrlen + p->ip_hdrlen);
				p->t_hdrlen = udphdrlen;
				p->port_dst = ntohs(udp->dest);
				p->port_src = ntohs(udp->source);
			}
			break;
			*/
		case IPPROTO_ICMP:

			return false; /* ignore ICMP */
			/*
			 {
				struct icmphdr *icmp = (struct icmphdr *)(buf + ethhdrlen + p->ip_hdrlen);
				p->t_hdrlen = icmphdrlen;
			}
			break;
			*/
		default: /* discard any other things */
			return false;
	}

	return true;
}

static inline bool packet_payload_isEmpty(const YasuIpv4 *p, uint16_t readed) {
	return ethhdrlen + p->ip_hdrlen + p->t_hdrlen == readed;
}

static void packet_payload_print(const YasuIpv4 *p, const char *buf, uint16_t readed) {

#define CHUNK 24
	printf("Payload:\n");
	for (int i = ethhdrlen + p->ip_hdrlen + p->t_hdrlen, n; i < readed; i+=CHUNK) {

		n = (CHUNK > readed-i ? readed-i : CHUNK); fprintf(stdout, "| ");

		displayChunk(buf+i, n >> 1, HEX, stdout);
		for (int j = n >> 1; j < CHUNK >> 1; j++) fprintf(stdout, "%-3c", ' '); /* padding */

		fprintf(stdout, " ");
		displayChunk(buf+i+(n >> 1), (n >> 1) + n%2, HEX, stdout);
		for (int j = (n >> 1) + n%2; j < CHUNK >> 1; j++) fprintf(stdout, "%-3c", ' ');
		fprintf(stdout, "| ");

		displayChunk(buf+i, n, ASCII, stdout);
		for (int j = n; j < CHUNK; j++) fprintf(stdout, "%-1c", ' '); 
		fprintf(stdout, " |\n");
	}

	printf("\n");
#undef CHUNK

}


int main(int argc, char *argv[]) {

	YasuIpv4 pk;
	struct ifreq ifr;
	uint16_t readed;
	char buf[ETHER_MAX_LEN]; /* max MTU: 1500 */

	argv[0] = basename(argv[0]);
	atexit(close_rawsk);
	signal(SIGINT, exit);

	if (argc < 3) {
		fprintf(stderr, "usage: %s -i <interface>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	/* htons is unnecessary but i have read somewhere that is a good practice
        so i keep htons() like memo for remember that i have read this thing somewhere
       	and i should check to get a decision */

	/* man 7 raw */
	/* ETH_P_IP doesn't show outgoing packets */
	if ((socket_raw = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))  == -1) {
		fprintf(stderr, "err socket initialization: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (!setpromisc(&ifr, argv[2], socket_raw)) {
		fprintf(stderr, "err setting promisc mode on interface %s: %s\n", argv[2], strerror(errno));
		exit(EXIT_FAILURE);
	}

	printf("%s running on interface %s\n", argv[0], argv[2]);

	// sudo hping3 -a 192.178.0.0 192.168.1.1 -p 1111 -d 10
	// TODO reassemble ip fragments ?

	while (1) {
		if ((readed = recvfrom(socket_raw, buf, ETH_FRAME_LEN, 0, NULL, NULL)) > 0) {
			if (packet_init(buf, &pk, readed) && !packet_payload_isEmpty(&pk, readed)) {

#if 0
				if (strcmp("192.178.0.0", pk.ip_src) != 0)
					continue;
#endif

				printf("protocol name: %s\n", pk.protocol->p_name);
				printf("protocol num (IANA): %d\n", pk.protocol->p_proto); 
				printf("src ip: %s\n", pk.ip_src);
				printf("dst ip: %s\n", pk.ip_dst);
				printf("src port: %hu\n", pk.port_src);
				printf("dst port: %hu\n", pk.port_dst);

				printf("src mac: %s\n", pk.mac_src);
				printf("dst mac: %s\n", pk.mac_dst);
				
				packet_payload_print(&pk, buf, readed);
				fflush(stdout);
			}

		}
	}

	exit(EXIT_SUCCESS);
}
