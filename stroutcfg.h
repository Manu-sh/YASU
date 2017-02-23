// example: /dev/null, /dev/stdout, ./yasu.log ..
#define FOPEN_STDOUT "/dev/stdout"
#define FOPEN_STDLOG "/dev/null"

#define OUT_IP_BEGIN "|IP   |\n"
#define OUT_IP_PROTOCOL "\tprotocol name: %s (IANA protocol no %d)\n"
#define OUT_IP_TOT_LEN "\ttotal lenght: %hu\n"
#define OUT_IP_FRAGMENTATION_OFFSET "\tfragmentation offset: %hu\n"
#define OUT_IP_TTL "\ttime to alive: %d\n"
#define OUT_IP_CHECKSUM "\tchecksum: %hu\n"
#define OUT_IP_SRC_IP "\tsource address: %s\n"
#define OUT_IP_DST_IP "\tdestination address: %s\n"

#define OUT_TCP_BEGIN "|TCP |\n"
#define OUT_TCP_SRC_PORT "\tsource port: %hu\n"
#define OUT_TCP_DST_PORT "\tdestination port: %hu\n"
#define OUT_TCP_DOFF "\tdata offset (tcp header length - word): %hu\n"

#define OUT_UDP_BEGIN "|UDP |\n"
#define OUT_UDP_SRC_PORT "\tsource port: %hu\n"
#define OUT_UDP_DST_PORT "\tdestination port: %hu\n"
#define OUT_UDP_TOT_LEN "\tlength (byte - including payload): %hu\n"
#define OUT_UDP_CHECKSUM "\tchecksum: %hu\n"

#define OUT_ICMP_BEGIN "|ICMP|\n"
#define OUT_ICMP_TYPE "\ttype: %d\n"
#define OUT_ICMP_CODE "\tcode: %d\n"
#define OUT_ICMP_CHECKSUM "\tchecksum: %hu\n"

#define OUT_PAYLOAD_BEGIN "Payload:\n"
#define OUT_PAYLOAD_END "\n"
#define OUT_FINAL_REPORT "other: %llu | tcp : %llu | icmp : %llu | upd : %llu | %s\n"

#define LOG_IP_BEGIN "|IP   |\n"
#define LOG_IP_PROTOCOL "\tprotocol name: %s (IANA protocol no %d)\n"
#define LOG_IP_TOT_LEN "\ttotal lenght: %hu\n"
#define LOG_IP_FRAGMENTATION_OFFSET "\tfragmentation offset: %hu\n"
#define LOG_IP_TTL "\ttime to alive: %d\n"
#define LOG_IP_CHECKSUM "\tchecksum: %hu\n"
#define LOG_IP_SRC_IP "\tsource address: %s\n"
#define LOG_IP_DST_IP "\tdestination address: %s\n"


#define LOG_TCP_BEGIN "|TCP |\n"
#define LOG_TCP_SRC_PORT "\tsource port: %hu\n"
#define LOG_TCP_DST_PORT "\tdestination port: %hu\n"
#define LOG_TCP_DOFF "\tdata offset (tcp header length - word): %hu\n"

#define LOG_UDP_BEGIN "|UDP |\n"
#define LOG_UDP_SRC_PORT "\tsource port: %hu\n"
#define LOG_UDP_DST_PORT "\tdestination port: %hu\n"
#define LOG_UDP_TOT_LEN "\tlength (byte - including payload): %hu\n"
#define LOG_UDP_CHECKSUM "\tchecksum: %hu\n"

#define LOG_ICMP_BEGIN "|ICMP|\n"
#define LOG_ICMP_TYPE "\ttype: %d\n"
#define LOG_ICMP_CODE "\tcode: %d\n"
#define LOG_ICMP_CHECKSUM "\tchecksum: %hu\n"

#define LOG_PAYLOAD_BEGIN "Payload:\n"
#define LOG_PAYLOAD_END "\n"
#define LOG_FINAL_REPORT "other: %llu | tcp : %llu | icmp : %llu | upd : %llu | %s\n"
