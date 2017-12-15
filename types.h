#include <netinet/in.h>
#include <errno.h>

#define BSIZE ETH_FRAME_LEN+2 // ETH_FRAME_LEN Max. octets in frame sans (without) FCS

#define MINLEN_IP 6
#define MAXLEN_IP INET_ADDRSTRLEN

#define FALSE 0
#define TRUE 1
#define TYPES_H

#ifndef EXIT_FAILURE
	#define EXIT_FAILURE 1
#endif

#ifndef EXIT_SUCCESS
	#define EXIT_SUCCESS 0
#endif

#define WORD2BYTE(x) (x*4) // convert 32bit word 2 byte

typedef struct {
	char ip_src[MAXLEN_IP+1];
	char ip_dst[MAXLEN_IP+1];
	char proto_name[10];
	uint16_t port_src;
	uint16_t port_dst;
	uint16_t proto_num;
	uint16_t ip_hdrlen;
	uint16_t t_hdrlen; // trasported hdr len (tcp, udp etc...)
} Packet;

typedef struct {
	int32_t port;
	char *target_ip;
} Uflags;

extern int errno;
