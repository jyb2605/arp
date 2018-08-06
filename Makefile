all: send_arp

send_arp: arp.o
	gcc -g -o send_arp arp.o -lpcap

arp.o:
	gcc -g -c -o arp.o arp.c
	
clean:
	rm -rf arp.o send_arp
