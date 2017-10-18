#define MACOSX

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/if_ether.h>   // Ethernet Header
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <pthread.h>

#ifdef MACOSX
#include <net/if_dl.h>
#endif

#define INET_ADDRLEN 4

struct macAddr{
    uint8_t addr[6];
};

struct spoofArgs{
	pcap_t *handle;
	struct in_addr senderIP;
	struct in_addr targetIP;
	struct in_addr myIP;
	struct macAddr senderMAC;
	struct macAddr targetMAC;
	struct macAddr myMAC;
	struct spoofArgs *next;
};

struct iphdr {
	uint8_t	ihl:4,
		version:4;
	uint8_t	tos;
	uint16_t	tot_len;
	uint16_t	id;
	uint16_t	frag_off;
	uint8_t	ttl;
	uint8_t	protocol;
	uint16_t	check;
	uint32_t	saddr;
	uint32_t	daddr;
	/*The options start here. */
};

void usage( char *progName );
struct macAddr *resolveMAC( struct macAddr *senderMAC, struct macAddr *myMAC, struct in_addr *senderIP, struct in_addr *myIP, pcap_t *handle );
struct macAddr *resolveMyMAC( struct macAddr *myMAC, char *interface );
struct in_addr *resolveMyIP( struct in_addr *myIP, char *interface );
int infectARP( struct macAddr *senderMAC, struct in_addr *senderIP, struct macAddr *myMAC, struct in_addr *targetIP, pcap_t *handle );
char *macToStr( struct macAddr *MAC, char *dest );
void *intervalInfect(void *args);
