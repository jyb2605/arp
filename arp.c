#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define ETHER_HEADER_SIZE 14
const uint8_t MY_MAC_ADDRESS[6] = {0x00,0x0c,0x29,0xc2,0xbd,0xe9};
const uint8_t BROADCAST_MAC_ADDRESS[6] = {0Xff,0xff,0xff,0xff,0xff,0xff};
typedef struct _ether_header{
        uint8_t         destination_mac_address[6];
        uint8_t         source_mac_address[6];
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

int arpAttack(pcap_t*, char*, char*);
void sendArp(pcap_t*, uint32_t, uint32_t, uint8_t*, uint8_t*);
void printE(ether_header);
uint32_t ipParser(char*);

int arpAttack(pcap_t* handle, char* sender_ip, char* target_ip ){
	uint8_t	sender_mac_address[6];
	unsigned char* buffer;
	uint32_t sender_ips, target_ips;

	printf("!");

	sender_ips = ipParser(sender_ip);
	target_ips = ipParser(target_ip);

	printf("%x\n%x\n", sender_ips, target_ips);

//	sendArp(handle, sender_ip, target_ip, NULL, NULL);
	

}

void sendArp(pcap_t* handle, uint32_t sender_ip, uint32_t target_ip,
	uint8_t*  source_mac_address, uint8_t* destination_mac_address ){

	ether_header ether;
        arp_header arp;
	
	struct	pcap_pkthdr*	header;
	const	u_char*		packet;

	if(source_mac_address == NULL)
		memcpy(ether.source_mac_address, MY_MAC_ADDRESS, 6);
	else
                memcpy(ether.source_mac_address, source_mac_address, 6);

	if(destination_mac_address == NULL)
		memcpy(ether.destination_mac_address, BROADCAST_MAC_ADDRESS, 6);
	else
                memcpy(ether.destination_mac_address, destination_mac_address, 6);

	ether.type = 0x806;

	//printE(ether);

	arp.hardware_type = 0x1;
	arp.protocol_type = 0x0800;
	arp.hardware_address_length = 0x6;
	arp.protocol_address_length = 0x4;
	arp.option = 0x0;
	
	memcpy(arp.source_mac_address, ether.source_mac_address, 6);
	memcpy(arp.source_ip_address, sender_ip,4);
	memcpy(arp.destination_mac_address, ether.destination_mac_address, 6);
	memcpy(arp.destination_ip_address, target_ip, 4);

	while(1){
		int res = pcap_next_ex(handle, &header, &packet);
	
		if(res == 0)
			continue;
		if(res == -1 || res == -2)
			break;

		printf("%u bytes captured\n", header->caplen);

		memcpy(&ether, &packet[0], 14);
	}

}

int sendFakeArp(){
}



void printE(ether_header ether){
	int i;
              
      	for(i = 0; i<6; i++){
		if((unsigned char)ether.source_mac_address[i]<16)
			printf("%x", 0);
		printf("%x", ether.source_mac_address[i]);
                if(i!=5)
                	printf(":");
         }
         printf("\n");

  	 for(i = 0; i<6; i++){
		 if((unsigned char)ether.destination_mac_address[i]<16)
                        printf("%x", 0);
		 printf("%x", ether.destination_mac_address[i]);
		 if(i!=5)
			 printf(":");
	 }
	 printf("\n");

	 printf("%x\n", ether.type);

	 return;
}

uint32_t ipParser(char* str){
	uint32_t result = 0;
	char buffer[4];
	int i, j = 0;

	for(i=0; i<strlen(str); i++){
		if(str[i] == '.' || i == (strlen(str)-1)){
			buffer[j] = '\0';
			result += atoi(buffer);
			result <<= 8;
			j = 0;
			continue;
		}
		buffer[j] = str[i];
	}

	printf("%x\n", result);

	return result;
}


int main(int argc, char* argv[]){
	
	if (argc != 4) {
		fprintf(stderr, "syntax: arp <interface> <sender ip> <target ip>\n");
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if ( handle == NULL) {
		fprintf(stderr, "coldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	
	printf("@");

	arpAttack(handle, argv[2], argv[3]);


	return 0;
}
