#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <ctype.h>
#include <stropts.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/icmp.h>
#include <linux/igmp.h>
#include <time.h>

#include "stroutcfg.h"

/*	© Copyright 2017 Manu-sh s3gmentationfault@gmail.com
	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License.
	This program is distributed in the hope that it will be useful,	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the	GNU General Public License for more details.
	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>. */

#define BSIZE ETH_FRAME_LEN+2 // ETH_FRAME_LEN Max. octets in frame sans (without) FCS

int socket_raw = -1;

// these header have a fixed size
unsigned short ethhdrlen = sizeof(struct ethhdr);
unsigned short inaddrlen = sizeof(struct in_addr);
unsigned short udphdrlen = sizeof(struct udphdr);
unsigned short icmphdrlen = sizeof(struct icmphdr);
static long long other_, tcp_, icmp_, udp_, igmp_;

FILE *logfile = NULL, *output = NULL;

static void die (int i) {
	if (socket_raw >= 0) close(socket_raw);
	if (logfile) fclose(logfile);
	if (output) fclose(output);
	exit(0);
}


void parse_ip_packets(char *buf);
void print_ip_hdr(struct iphdr *ip);
void print_tcp(char *buf, unsigned short *iphdrlen);
void print_udp(char *buf, unsigned short *iphdrlen);
void print_icmp(char *buf, unsigned short *iphdrlen);
void print_payload(register char *buf, unsigned short skipbytes);
void setpromisc(struct ifreq *ifr, const char *iface, int *socket);

/* 	RFC 791 ip protocol: https://tools.ietf.org/html/rfc791#page-11
	RFC 793 tcp protocol: https://tools.ietf.org/html/rfc793#page-15
	RFC 768 udp protocol: https://tools.ietf.org/html/rfc768 */

void main(int argc, char *argv[]) {

	char buf[BSIZE] = "\0";
	char *iface = argv[1] ? argv[1] : "wlp4s0";
	struct ifreq ifr;

	signal(SIGINT, die);
	printf("%s running on interface %s\n", argv[0], iface);

	if ((socket_raw = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
		fprintf(stderr, "err socket syscall, are you root ?\n");
		return;
	}

	setpromisc(&ifr, iface, &socket_raw);
	logfile = fopen(FOPEN_STDLOG, "a");
	output = fopen(FOPEN_STDOUT, "a");

	if (!logfile) {
		fprintf(stderr, "err creating log file\n");
		die(0);
	}

	if (!output) {
		fprintf(stderr, "err opening default output file\n");
		die(0);
	}

	while (1) {
		if (recvfrom(socket_raw, buf, BSIZE-2, 0, NULL, NULL) > 0) parse_ip_packets(buf);
	}

	return;
}



void parse_ip_packets(char *buf) {

	struct iphdr *ip = (struct iphdr *)(buf + ethhdrlen);
	unsigned short iphdrlen = ip->ihl*4; // (word*4 = byte)

	switch (ip->protocol) {
		case IPPROTO_TCP:
			++tcp_;
			print_ip_hdr(ip);
			print_tcp(buf, &iphdrlen);
			break;
		case IPPROTO_UDP:
			++udp_;
			print_ip_hdr(ip);
			print_udp(buf, &iphdrlen);
			break;
		case IPPROTO_ICMP:
		//	++icmp_;
			return;
		//	print_ip_hdr(ip);
		//	print_icmp(buf, &iphdrlen);
		//	break;
		default:
			++other_;
			return;
	}

	time_t unix_mseconds;
	time(&unix_mseconds);

	fprintf(output,  OUT_FINAL_REPORT, other_, tcp_, icmp_, udp_, ctime(&unix_mseconds));
	fprintf(logfile, LOG_FINAL_REPORT, other_, tcp_, icmp_, udp_, ctime(&unix_mseconds));
}

void print_ip_hdr(struct iphdr *ip) {

	struct in_addr source, dest;

//	memset(&source, 0, inaddrlen);
//	memset(&dest, 0, inaddrlen);

	memcpy(&source.s_addr, &ip->saddr, inaddrlen);
	memcpy(&dest.s_addr, &ip->daddr, inaddrlen);

	fprintf(output,  OUT_IP_BEGIN);
	fprintf(logfile, LOG_IP_BEGIN);

	{
		struct protoent *p = getprotobynumber(ip->protocol);
		fprintf(output,  OUT_IP_PROTOCOL, p->p_name, p->p_proto);
		fprintf(logfile, LOG_IP_PROTOCOL, p->p_name, p->p_proto);
	}

	fprintf(output,  OUT_IP_TOT_LEN, ip->tot_len);
	fprintf(logfile, LOG_IP_TOT_LEN, ip->tot_len);

	fprintf(output,  OUT_IP_FRAGMENTATION_OFFSET, ip->frag_off);
	fprintf(logfile, LOG_IP_FRAGMENTATION_OFFSET, ip->frag_off);

	fprintf(output,  OUT_IP_TTL, ip->ttl);
	fprintf(logfile, LOG_IP_TTL, ip->ttl);

	fprintf(output,  OUT_IP_CHECKSUM, ip->check);
	fprintf(logfile, LOG_IP_CHECKSUM, ip->check);

	fprintf(output,  OUT_IP_SRC_IP, inet_ntoa(source));
	fprintf(logfile, LOG_IP_SRC_IP, inet_ntoa(source));

	fprintf(output,  OUT_IP_DST_IP, inet_ntoa(dest));
	fprintf(logfile, LOG_IP_DST_IP, inet_ntoa(dest));
}

void print_tcp(char *buf, unsigned short *iphdrlen) {

	struct tcphdr *tcp = (struct tcphdr *)(buf + ethhdrlen + *iphdrlen);
	unsigned short tcphdrlen = tcp->doff*4; // (word*4 = byte)

	fprintf(output,  OUT_TCP_BEGIN);
	fprintf(logfile, OUT_TCP_BEGIN);

	fprintf(output,  OUT_TCP_SRC_PORT, ntohs(tcp->source));
	fprintf(logfile, LOG_TCP_SRC_PORT, ntohs(tcp->source));

	fprintf(output,  OUT_TCP_DST_PORT, ntohs(tcp->dest));
	fprintf(logfile, LOG_TCP_DST_PORT, ntohs(tcp->dest));

	fprintf(output,  OUT_TCP_DOFF, tcp->doff);
	fprintf(logfile, LOG_TCP_DOFF, tcp->doff);

	print_payload(buf, (ethhdrlen + *iphdrlen + tcphdrlen));
}

void print_udp(char *buf, unsigned short *iphdrlen) {

	struct udphdr *udp = (struct udphdr *)(buf + ethhdrlen + *iphdrlen);
	fprintf(output,  OUT_UDP_BEGIN);
	fprintf(logfile, LOG_UDP_BEGIN);

	fprintf(output,  OUT_UDP_SRC_PORT, ntohs(udp->source));
	fprintf(logfile, LOG_UDP_SRC_PORT, ntohs(udp->source));

	fprintf(output,  OUT_UDP_DST_PORT, ntohs(udp->dest));
	fprintf(logfile, LOG_UDP_DST_PORT, ntohs(udp->dest));

	fprintf(output,  OUT_UDP_TOT_LEN, ntohs(udp->len));
	fprintf(logfile, LOG_UDP_TOT_LEN, ntohs(udp->len));

	fprintf(output,  OUT_UDP_CHECKSUM, udp->check);
	fprintf(logfile, LOG_UDP_CHECKSUM, udp->check);

	print_payload(buf, (ethhdrlen + *iphdrlen + udphdrlen));
}

void print_icmp(char *buf, unsigned short *iphdrlen) {

	struct icmphdr *icmp = (struct icmphdr *)(buf + ethhdrlen + *iphdrlen);
	fprintf(output,  OUT_ICMP_BEGIN);
	fprintf(logfile, LOG_ICMP_BEGIN);

	fprintf(output,  OUT_ICMP_TYPE, icmp->type);
	fprintf(logfile, LOG_ICMP_TYPE, icmp->type);

	fprintf(output,  OUT_ICMP_CODE, icmp->code);
	fprintf(logfile, LOG_ICMP_CODE, icmp->code);

	fprintf(output,  OUT_ICMP_CHECKSUM, icmp->checksum);
	fprintf(logfile, LOG_ICMP_CHECKSUM, icmp->checksum);
}


// header length to be skipped (in bytes), buf must to be null terminated
void print_payload(register char *buf, unsigned short skipbytes) {

	fprintf(output,  OUT_PAYLOAD_BEGIN);
	fprintf(logfile, LOG_PAYLOAD_BEGIN);

	for (buf += skipbytes; *buf; buf++) {
		if (isprint(*buf)) {
			fprintf(output, "%c", *buf);
			fprintf(logfile, "%c", *buf);
		} else {
			fprintf(output, ".");
			fprintf(logfile, ".");
		}
	}

	fprintf(output,  OUT_PAYLOAD_END);
	fprintf(logfile, LOG_PAYLOAD_END);
}

void setpromisc(struct ifreq *ifr, const char *iface, int *socket) {

	memset(ifr, 0, sizeof(struct ifreq));
	strcpy(ifr->ifr_name, iface);

	// SIOCGIFFLAGS => GET
	if ((ioctl(*socket, SIOCGIFFLAGS, ifr)) == -1) {
		fprintf(stderr, "err getting configurations from interface %s\n", iface);
		die(0);
	}

	// SIOCSIFFLAGS => SET
	ifr->ifr_flags |= IFF_PROMISC;
	if ((ioctl(*socket, SIOCSIFFLAGS, ifr)) == -1) {
		fprintf(stderr, "err setting promisc mode on interface %s\n", iface);
		die(0);
	}

	if ((ifr->ifr_flags & IFF_PROMISC) != 0) {
		printf("[*] %s promiscuos mode enabled\n", ifr->ifr_name);
	} else {
		fprintf(stderr, "err setting interface %s in promiscuos mode.\n", ifr->ifr_name);
		die(0);
	}

}
