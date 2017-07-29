#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#define MAC_BUF_LEN 20

void get_mac(void);
typedef struct ether_header ether_header; //ethernet.h
typedef struct ether_arp ether_arp; //if_ether.h

const char *kStringMacAddree = "/sys/class/net/eth0/address";

int main(int argc, char *argv[])
{

	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	u_char *packet;		/* The actual packet */

	/* Define the device */
/*
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
*/
	/* Find the properties for the device */
/*
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
*/

	/* Open the session in promiscuous mode */
/*
   handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
*/
	/* Compile and apply the filter */
/*
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
*/
	get_mac();
	make_eth(packet);
	

	
//	pcap_next_ex(handle, &header,&packet);
//	pcap_close(handle);
	return(0);
}

void get_mac(void)
{
	FILE *fp = fopen(kStringMacAddree, "r");
	char mac[MAC_BUF_LEN] = {'\0', };
	ether_header ether;

	fgets(mac, MAC_BUF_LEN, fp);
	for(int i=0;i<ETH_ALEN;i++){
		ether.ether_dhost[i] = strtol(&mac[i*3], NULL, 16);
		printf("%02X :",ether.ether_dhost[i]);
	}

	fclose(fp);
}

void make_eth(u_char *packet)
{
	ether_header *ether;
	ether=(ether_header *)packet;
	memset(ether->ether_shost,0xff,ETH_ALEN);
	ether_type=ETHERTYPE_ARP;
}

void make_arp(u_char *packet)
{
	eth_arp *arp;
	packet+=sizeof(ether_header);
	arp=(eth_arp *)packet;

	


}
