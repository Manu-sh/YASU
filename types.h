#include <netdb.h>
#include <netinet/in.h>
#include <linux/if_ether.h>

#define DWORD2BYTE(x) (x*4)         /* convert 32bit word to byte */

/* ETH_ALEN: octets in one ethernet addr, defined into if_ether.h */
#define MAC_ADDRSTRLEN (3*ETH_ALEN) /* XX:XX:XX:XX:XX:XX including null */

typedef struct {

	struct protoent *protocol;

	char ip_src[INET_ADDRSTRLEN]; /* ip max length including null */
	char ip_dst[INET_ADDRSTRLEN];

	char mac_src[MAC_ADDRSTRLEN];
	char mac_dst[MAC_ADDRSTRLEN];

	uint16_t port_src;
	uint16_t port_dst;

	uint16_t t_hdrlen;  /* trasported hdr len (tcp, udp etc...) */

} YasuIpv4;
