#include "packet.h"

// these header have a fixed size (eth, udp, icmp)
const static unsigned short ethhdrlen  = sizeof(struct ethhdr);
const static unsigned short udphdrlen  = sizeof(struct udphdr);
const static unsigned short icmphdrlen = sizeof(struct icmphdr);

const static unsigned short inaddrlen  = sizeof(struct in_addr);

bool packet_init(char *buf, Packet *pk) {

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
		strcpy(pk->ip_src, inet_ntoa(dest));
		strcpy(pk->ip_dst, inet_ntoa(source));
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
			{
				struct icmphdr *icmp = (struct icmphdr *)(buf + ethhdrlen + pk->ip_hdrlen);
				pk->t_hdrlen = icmphdrlen;
			}
			break;
		default:
			return FALSE;
	}


	return TRUE;

}

bool isPresentPayload(Packet *p, register char *buf, register unsigned short readed) {

	for (register unsigned short i = (ethhdrlen + p->ip_hdrlen + p->t_hdrlen); i < readed; i++)
		if (buf[i] != '\0')
			return TRUE;

	return FALSE;

}

// header length to be skipped (in bytes), buf must to be null terminated
void print_payload(Packet *p, register char *buf, register unsigned short readed) {

	printf("Payload: ");
	for (register unsigned short i = (ethhdrlen + p->ip_hdrlen + p->t_hdrlen); i < readed; i++) {
		if (isprint(buf[i]))
			printf("%c", buf[i]);
		else
			printf(".");
	}
	printf("\n");

}
