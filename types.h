#define BSIZE ETH_FRAME_LEN+2 // ETH_FRAME_LEN Max. octets in frame sans (without) FCS

#define MINLEN_IP 6
#define MAXLEN_IP 14

#define FALSE 0
#define TRUE 1
#define TYPES_H

#ifndef EXIT_FAILURE
	#define EXIT_FAILURE 1
#endif

#ifndef EXIT_SUCCESS
	#define EXIT_SUCCESS 0
#endif

#define WORD2BYTE(x) (x*4)
#define S_FREE(x) free(x); x = NULL;

struct packet {
	char ip_src[MAXLEN_IP+1];
	char ip_dst[MAXLEN_IP+1];
	char proto_name[10];
	uint16_t port_src;
	uint16_t port_dst;
	uint16_t proto_num;
	uint16_t ip_hdrlen;
	uint16_t t_hdrlen; // trasported hdr len (tcp, udp etc...)
};

struct user_pfflags {
	int32_t port;
	char *target_ip;
};

typedef struct packet Packet;
typedef struct user_pfflags Uflags;
