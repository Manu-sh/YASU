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

#include "packet.h"

int socket_raw = -1;
long long other_, tcp_, icmp_, udp_, igmp_;

static void die (int i) {
	if (socket_raw >= 0) close(socket_raw);
	exit(i);
}

void setpromisc(struct ifreq *ifr, const char *iface, int *socket);
bool isIp(char *ip);
bool isPort(char *port);
bool packet_filtr(Packet *p, Uflags *uf);

Uflags uf = { 0, NULL };

/* 	RFC 791 ip protocol: https://tools.ietf.org/html/rfc791#page-11
	RFC 793 tcp protocol: https://tools.ietf.org/html/rfc793#page-15
	RFC 768 udp protocol: https://tools.ietf.org/html/rfc768 */


/*	© Copyright 2017 Manu-sh s3gmentationfault@gmail.com
	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License.
	This program is distributed in the hope that it will be useful,	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the	GNU General Public License for more details.
	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>. */

int main(int argc, char *argv[]) {

	char *target = NULL;
	char buf[BSIZE] = "\0";
	char *iface = NULL;
	unsigned short readed;
	int c, bytes;

	struct ifreq ifr;
	Packet pk;

	signal(SIGINT, die);

	opterr = 0;
	while ((c = getopt (argc, argv, "i:t:p:")) != -1) {

		switch (c) {
			case 'i':
				iface = (optarg) ? optarg : "wlp4s0";
				break;
			case 't':
				uf.target_ip = isIp(optarg) ? optarg : NULL;
				if (!uf.target_ip) {
					fprintf(stderr, "the ip %s is not a valid ip\n", uf.target_ip);
					die(EXIT_FAILURE);
				}
				printf("the target ip is %s\n", uf.target_ip);
				break;
			case 'p':
				uf.port = isPort(optarg) ? (unsigned short)atol(optarg) : -1;
				if (uf.port == -1) {
					fprintf(stderr, "the port %d is not a valid port\n", uf.port);
					die(EXIT_FAILURE);
				}
				printf("the target port is %d\n", uf.port);
				break;
		}

	}

	if (!iface) {
		printf("usage: %s -i <interface>\n", argv[0]);
		die(EXIT_FAILURE);
	}

	printf("%s running on interface %s\n", argv[0], iface);

	if ((socket_raw = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
		fprintf(stderr, "err socket syscall, are you root ?\n");
		die(EXIT_FAILURE);
	}

	setpromisc(&ifr, iface, &socket_raw);

	while (1) {
		if ((readed = recvfrom(socket_raw, buf, BSIZE-2, 0, NULL, NULL)) > 0) {
			if (packet_init(buf, &pk) && packet_filtr(&pk, &uf) && isPresentPayload(&pk, buf, readed)) {
				printf("protocol name: %s\n", pk.proto_name);
				printf("protocol num: %hu\n", pk.proto_num);
				printf("src ip: %s\n", pk.ip_src);
				printf("dst ip: %s\n", pk.ip_dst);
				printf("src port: %hu\n", pk.port_src);
				printf("dst port: %hu\n", pk.port_dst);
				print_payload(&pk, buf, readed);
				fflush(stdout);
			}
		}
	}

	die(EXIT_SUCCESS);
}


void setpromisc(struct ifreq *ifr, const char *iface, int *socket) {

	memset(ifr, 0, sizeof(struct ifreq));
	strcpy(ifr->ifr_name, iface);

	// SIOCGIFFLAGS => GET
	if ((ioctl(*socket, SIOCGIFFLAGS, ifr)) == -1) {
		fprintf(stderr, "err getting configurations from interface %s\n", iface);
		die(EXIT_FAILURE);
	}

	// SIOCSIFFLAGS => SET
	ifr->ifr_flags |= IFF_PROMISC;
	if ((ioctl(*socket, SIOCSIFFLAGS, ifr)) == -1) {
		fprintf(stderr, "err setting promisc mode on interface %s\n", iface);
		die(EXIT_FAILURE);
	}

	if ((ifr->ifr_flags & IFF_PROMISC) != 0) {
		printf("[*] %s promiscuos mode enabled\n", ifr->ifr_name);
	} else {
		fprintf(stderr, "err setting interface %s in promiscuos mode.\n", ifr->ifr_name);
		die(EXIT_FAILURE);
	}

}

bool packet_filtr(Packet *p, Uflags *uf) {

	if (!uf->target_ip)
		goto ctl_port;

	if (strcmp(uf->target_ip, p->ip_src) != 0 && strcmp(uf->target_ip, p->ip_dst) != 0)
		return FALSE;

ctl_port:

	// 0 == traffic from/to all port accepted
	if (!uf->port || uf->port == p->port_src || uf->port == p->port_dst)
		return TRUE;

	return FALSE;

}


bool isIp(char *ip) { return (inet_addr(ip) != INADDR_NONE); }
bool isPort(char *port) { return ((unsigned short)atol(optarg) > 0); }
