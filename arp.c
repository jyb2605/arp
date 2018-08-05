#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define ETHER_HEADER_SIZE 14

typedef struct _ether_header{
        uint8_t         source_mac_address[6];
        uint8_t         destination_mac_address[6];
	uint16_t	type;
}ether_header;

typedef struct _arp_header{
	uint16_t	hardware_type;
	uint16_t	protocol_type;
	uint8_t		hardware_address_length;
	uint8_t		protocol_address_length;
	uint16_t	option;
	uint8_t		source_mac_address[6];
	uint8_t		source_ip_address[4];
	uint8_t         destination_mac_address[6];
        uint8_t         destination_ip_address[4];
}arp_header;

int main(int argc, char* argv[]){

	ether_header	ether;
	arp_header	arp;
	
	if (argc != 2) {
		fprintf(stderr, "syntax: arp <interface>\n");
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pacp_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if ( handle == NULL) {
		fprintf(stderr, "coldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	printf("%d %d\n", (int)sizeof(ether), (int)sizeof(arp));

	return 0;
}
