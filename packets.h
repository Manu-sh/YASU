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

#define PACKET_H

#ifndef TYPES_H
	#include "types.h"
#endif

// these header have a fixed size (eth, udp, icmp)
const uint16_t ethhdrlen  = sizeof(struct ethhdr);
const uint16_t udphdrlen  = sizeof(struct udphdr);
// const uint16_t icmphdrlen = sizeof(struct icmphdr);

static bool packet_init(char *buf, Packet *pk) {

// TODO add macaddress to packet info
#if 0
	// https://stackoverflow.com/questions/31090616/printf-adds-extra-ffffff-to-hex-print-from-a-char-array
	struct ethhdr *ethframe = (struct ethhdr *)buf;

	for (int i = 0; i < ETH_ALEN; i++)
		printf("%02X ", ethframe->h_dest[i]);
	puts("");

	for (int i = 0; i < ETH_ALEN; i++)
		printf("%02X ", ethframe->h_source[i]);
	puts("");
#endif


	memset(pk, 0, sizeof(Packet));

	struct iphdr *ip = (struct iphdr *)(buf + ethhdrlen);
	pk->proto_num = ip->protocol;
	pk->ip_hdrlen = WORD2BYTE(ip->ihl);

	{
		struct protoent *p = getprotobynumber(ip->protocol);
		struct in_addr source, dest;
		memcpy(&source.s_addr, &ip->saddr, sizeof(struct in_addr));
		memcpy(&dest.s_addr, &ip->daddr, sizeof(struct in_addr));
		strcpy(pk->proto_name, p->p_name);
		strcpy(pk->ip_src, inet_ntoa(source));
		strcpy(pk->ip_dst, inet_ntoa(dest));
	}


	switch (pk->proto_num) {
		case IPPROTO_TCP:
			{
				struct tcphdr *tcp = (struct tcphdr *)(buf + ethhdrlen + pk->ip_hdrlen);
				pk->t_hdrlen = WORD2BYTE(tcp->doff);
				pk->port_dst = ntohs(tcp->dest);
				pk->port_src = ntohs(tcp->source);
			}
			break;
		case IPPROTO_UDP:
			{
				struct udphdr *udp = (struct udphdr *)(buf + ethhdrlen + pk->ip_hdrlen);
				pk->t_hdrlen = udphdrlen;
				pk->port_dst = ntohs(udp->dest);
				pk->port_src = ntohs(udp->source);
			}
			break;
		case IPPROTO_ICMP:

			return FALSE; // ignore ICMP
			/*
			{
				struct icmphdr *icmp = (struct icmphdr *)(buf + ethhdrlen + pk->ip_hdrlen);
				pk->t_hdrlen = icmphdrlen;
			}*/
			break;
		default:
			return FALSE;
	}


	return TRUE;

}

static bool isPresentPayload(Packet *p, register char *buf, register uint16_t readed) {

	for (uint16_t i = (ethhdrlen + p->ip_hdrlen + p->t_hdrlen); i < readed; i++)
		if (buf[i] != '\0')
			return TRUE;

	return FALSE;

}

// header length to be skipped (in bytes), buf must to be null terminated
static void print_payload(Packet *p, register char *buf, register uint16_t readed) {

	printf("Payload: ");
	for (uint16_t i = (ethhdrlen + p->ip_hdrlen + p->t_hdrlen); i < readed; i++)
		printf("%c", isprint(buf[i]) ? buf[i] : '.');

	printf("\n");

}
