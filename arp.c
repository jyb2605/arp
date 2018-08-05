#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define ETHER_HEADER_SIZE 14

struct _ether_header{
	unsigned long	header;
        uint8_t         source_mac_address[6];
        uint8_t         destination_mac_address[6];
}ether_header;

struct _arp_header{
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

	printf("%d %d\n", (int)sizeof(ether), (int)sizeof(arp));

	return 0;
}
