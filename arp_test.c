#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#define ETH_ALEN 6

typedef struct ether_header // ..xx/net/ethernet.h
{ 
	u_int8_t ether_dhost[ETH_ALEN]; //1BYTE
   	u_int8_t ether_shost[ETH_ALEN]; //1BYTE
	u_int16_t ether_type //2BYTE
}ether_header;

typedef struct iphdr // ..xx/linux/ip.h
{
	u_int8_t ihl:4 //header length 4bit
	u_int8_t version:4 //version 4bit
	u_int8_t tos;		//type of service
	u_int16_t tot_len;	//total length 2byte
	u_int16_t id;		//identification
	u_int16_t frag_off;	//fragment offset field
	u_int8_t ttl;		//time to live
	u_int8_t protocol; //protocol
	u_int16_t check;	//check sum
	struct in_addr ip_src;//src ip
	struct in_addr ip_dst;
}iphdr;

typedef struct ether_arp
{
	u_int16_t ar_hrd;
	u_int16_t ar_pro;
	u_int8_t ar_hln;
	u_int8_t ar_pln;
	u_int16_t ar_op;
	u_int8_t arp_src_mac[ETHER_ALEN];
	struct in_addr arp_src_ip;
	u_int8_t arp_dst_mac[ETHER_ALEN];
	struct in_addr arp_dst_ip;
}ether_arp;

void get_mac(u_char *packet)
{

	FILE *fp;
	char mac[6];
	ether_header *ether;
	ether=(ether_header *)packet;
	ether->ether_dhost
	/*if(fD=fopen("/sys/class/net/eth0/address","r"))
	{
		fp=strtol(fp,NULL,16);
		fget(ether->ether_dhost,ETH_ALEN,fp);

	}*?
}

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
	const u_char *packet;		/* The actual packet */

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* Open the session in promiscuous mode */
	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}


	pcap_next_ex(handle, &header,&packet);
	pcap_close(handle);
	return(0);
}
