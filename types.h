#include <netdb.h>
#include <netinet/in.h>
#include <linux/if_ether.h>

/* compiler should be optimize x*4 into x << 2 and 3*ETH_ALEN into
(ETH_ALEN << 2) - ETH_ALEN if they are used at runtime otherwise
should be replace with a constant if it don't do this doesn't matter */

#define DWORD2BYTE(x) (x*4) /* convert 32bit word to byte */

/* ETH_ALEN: octets in one ethernet addr, defined into if_ether.h */
#define MAC_ADDRSTRLEN (3*ETH_ALEN+1) /* XX:XX:XX:XX:XX:XX including null */

#define INET_ADDR_SIZE  (INET_ADDRSTRLEN+1) /* 255.255.255.255 including null */

typedef struct {

	struct protoent *protocol;

	char ip_src[INET_ADDR_SIZE]; /* ip max length including null */
	char ip_dst[INET_ADDR_SIZE];

	char mac_src[MAC_ADDRSTRLEN];
	char mac_dst[MAC_ADDRSTRLEN];

	uint16_t port_src;
	uint16_t port_dst;

	uint16_t ip_hdrlen;
	uint16_t t_hdrlen;  /* trasported hdr len (tcp, udp etc...) */

} YasuPacket;

