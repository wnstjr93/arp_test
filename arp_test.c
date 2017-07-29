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
void make_eth(u_char *packet);
void make_arp(u_char *packet);

typedef struct ether_header ether_header; //ethernet.h
typedef struct ether_arp ether_arp; //if_ether.h

const char *kMacDirectory = "/sys/class/net/eth0/address";

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
//	make_arp(packet);

	
//	pcap_next_ex(handle, &header,&packet);
//	pcap_close(handle);
	return(0);
}

void get_mac(void)
{
	FILE *fp = fopen(kMacDirectory, "r");
	char mac[MAC_BUF_LEN] = {'\0', };
	ether_header ether;

	fgets(mac, MAC_BUF_LEN, fp);
	for(int i=0;i<ETH_ALEN;i++){
		ether.ether_shost[i] = strtol(&mac[i*3], NULL, 16);
		if(i!=ETH_ALEN-1)printf("%02X :",ether.ether_dhost[i]);
		else printf("%02X\n",ether.ether_dhost[i]);
	}

	fclose(fp);
}

void make_eth(u_char *packet)
{
	ether_header *ether;
	ether=(ether_header *)packet;
	//memset(ether->ether_dhost,'\xff',ETH_ALEN);
	
	ether->ether_type=htons(ETHERTYPE_ARP);
	printf("eth_dho:");
	for(int i=0;i<ETH_ALEN;i++)
	printf("%02X : ",ether->ether_type);
	printf("%04X",ether->ether_type);
}
void make_arp(u_char *packet)
{

	u_int16_t hd_type=0x0001;
	u_int16_t pro_type=0x0800;
	u_char hd_size=0x06;
	u_char pro_size=0x04;
	u_int16_t opcode=0x0001;
	ether_header *ether;
	ether_arp *arp;
	
	packet+=sizeof(ether_header);
	arp=(ether_arp *)packet;
	
	/*ether_arp -  arphdr ea_hdr*/
	arp->ea_hdr.ar_hrd=htons(hd_type);
	arp->ea_hdr.ar_pro=htons(pro_type);
	arp->ea_hdr.ar_hln=(hd_size);
	arp->ea_hdr.ar_pln=(pro_size);
	arp->ea_hdr.ar_op=htons(opcode);
	/*change like define!*/
	printf("arp_sMAC:");
	for(int i=0;i<ETH_ALEN;i++){
		arp->arp_sha[i]=ether->ether_shost[i];
		if(i!=ETH_ALEN-1)printf("%02X :",arp->arp_sha[i]);
		else printf("%02X\n",arp->arp_sha[i]);
	}
	inet_pton(AF_INET,"192.168.32.217",arp->arp_spa);
		memset(arp->arp_tha,0x00,ETH_ALEN);
		for(int i=0;i<ETH_ALEN;i++){
			if(i!=ETH_ALEN-1)printf("%02X :",arp->arp_tha[i]);
			else printf("%02X\n",arp->arp_tha[i]);
		}
	inet_pton(AF_INET,"192.168.32.254",arp->arp_tpa);
}






