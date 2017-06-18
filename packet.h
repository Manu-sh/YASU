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

bool packet_init(char *buf, Packet *pk);
bool isPresentPayload(Packet *p, register char *buf, register uint16_t readed);
void print_payload(Packet *p, register char *buf, register uint16_t readed);
