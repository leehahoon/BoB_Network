#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <pcap.h>
#include <libnet.h>

#define MAXBUF 0xFFFF
#define flag 47
#define checksum 50

int checkcheck(unsigned char *data, int dlen) {
  int i, chksum = 0;
  unsigned short *shorter = (unsigned short *)data;

  for (i = 0; i < dlen; ++i) {
    chksum += shorter[i];
  }

  if (dlen & 1) {
    chksum += shorter[i]  & 0x00ff;
  }

  chksum = (chksum >> 16) + (chksum & 0xFFFF);
  chksum += (chksum >> 16);

  chksum ^= 0xFFFF;
  return chksum;
}


int main(){        
	char errbuf[PCAP_ERRBUF_SIZE];        
	char * Device;
	int data_flag=0;
	u_char * block="blocked";
	u_char * location="HTTP/1.1 302 Found\nLocation: https://en.wikipedia.org/wiki/HTTP_302";
	int loca_len = strlen(location);
	u_short * check_sum;
	Device = pcap_lookupdev(errbuf);        
	printf("%s\n",Device);   
	struct libnet_ether_addr *client_mac_addr;
	struct libnet_ether_addr *server_mac_addr;
	u_int8_t client_mac[6] = {0,};
	u_int8_t server_mac[6] = {0,};
	u_int8_t client_ip[4] = {0,};
	u_int8_t server_ip[4] = {0,};
	u_int8_t client_port[2] = {0,};
	u_int8_t server_port[2] = {0,};
	int tcpdata_len;
	int iphdr_len;
	int tcpdata;
	int tcphdr;
	int tcplen;
	char *iphdr;
	unsigned short aa;
	unsigned char * tcpchecksum;
	unsigned char *ptr=(unsigned char*)&tcplen;
	unsigned char *ptr2=(unsigned char*)&aa;
	pcap_t * pPcap;
	libnet_t *l;
	pPcap = pcap_open_live(Device,1500, 1, 0, errbuf); 
	
	int i,j,k=0,length; 
	if(NULL == pPcap) {            
		printf("%s\n",errbuf);            
		return 0;        
	}
	
	l = libnet_init(LIBNET_LINK, Device, errbuf);
 	if ( l == NULL ) {
   		fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
   		exit(EXIT_FAILURE);
 	}

	client_mac_addr = libnet_get_hwaddr(l);
	for(i=0;i<6;i++)
		client_mac[i] = client_mac_addr->ether_addr_octet[i];	

  	length=strlen(block);
	u_char * pData;
	struct pcap_pkthdr h;
	while(1){        
		pData = pcap_next(pPcap, &h);
		
		for(i=0;i<h.caplen;i++){
                        if(isprint(*(pData))){
                                if(*(pData+i)=='G' && *(pData+i+1)=='E' && *(pData+i+2)=='T'){
					pData[flag]|=4;
					if(*(pData+46)==128) tcphdr=32;
					else tcphdr=20;
					sprintf(iphdr,"0x%02x%02x",pData[16],pData[17]);
					iphdr_len = strtoul(iphdr,NULL,16);
					iphdr_len-=20;
					iphdr_len-=tcphdr;	
					printf("TCP Data Length: %d\n",iphdr_len);
					tcpdata=14;
					tcpdata+=20;
					tcpdata+=tcphdr;
					printf("TCP Data Location : %d\n",tcpdata);
					for(j=tcpdata;j<h.caplen;j++)
						pData[j]='\0';
					
					for(j=0;j<7;j++)
						*(pData+tcpdata+j)=block[j];
					
					for(j=0;j<6;j++)
                                                server_mac[j] = *(pData+j);

                                        for(j=0;j<4;j++){
                                                client_ip[j] = *(pData+j+26);
                                                server_ip[j] = *(pData+j+30);
                                        }

                                        for(j=0;j<2;j++){
                                                client_port[j]=*(pData+j+34);
                                                server_port[j]=*(pData+j+36);
                                        }
					tcpchecksum = (unsigned char *)malloc(tcphdr+iphdr_len+12);
					for(j=0;j<4;j++){
						tcpchecksum[j]=client_ip[j];
						tcpchecksum[j+4]=server_ip[j];
					}
					tcpchecksum[8]='\x00';
					tcpchecksum[9]='\x06';
					
					tcplen=tcphdr+iphdr_len;
					tcpchecksum[10]=ptr[1];
					tcpchecksum[11]=ptr[0];
					for(j=12;j<tcphdr+12;j++){
						tcpchecksum[j]=pData[j+21];
					}
					tcpchecksum[29]='\x00';
					tcpchecksum[30]='\x00';
					
					for(j=tcphdr+12;j<iphdr_len+tcphdr+12;j++){
						tcpchecksum[j]=pData[tcpdata+k];
						k++;
					}
					k=0;
					for(j=0;j<31+iphdr_len;j++){
						if(j==13) puts("");
						printf("%02x ",tcpchecksum[j]);
					}
					printf("\n");
					aa = checkcheck(tcpchecksum, tcphdr+iphdr_len+12);
					pData[checksum]=ptr[1];
					pData[checksum+1]=ptr[0];
					unsigned int syntmp = *((unsigned int *)&pData[38]);
					syntmp = ntohl(syntmp) + iphdr_len;
					pData[38] = syntmp >> 24;
					pData[39] = (syntmp >> 16) & 0xFF;
					pData[40] = (syntmp >> 8) & 0xFF;
					pData[41] = syntmp & 0xFF;
					pcap_sendpacket(pPcap, pData, h.caplen);
					printf("TCP HDR + DATA : %d\n",tcplen);
					
					for(j=0;j<6;j++){       
	                			pData[j]=client_mac[j];
	                       			pData[j+6]=server_mac[j];
	                		}
					for(j=0;j<4;j++){
						pData[j+26]=server_ip[j];
						pData[j+30]=client_ip[j];
					}
					for(j=0;j<2;j++){
						pData[j+34]=server_port[j];
						pData[j+36]=client_port[j];
					}
					for(j=0;j<loca_len;j++)
                                                *(pData+tcpdata+j)=location[j];
					
					printf("%02x%02x%02x%02x\n",pData[38],pData[39],pData[40],pData[41]);
					syntmp = syntmp - iphdr_len;
					pData[38] = syntmp >> 24;
                                        pData[39] = (syntmp >> 16) & 0xFF;
                                        pData[40] = (syntmp >> 8) & 0xFF;
                                        pData[41] = syntmp & 0xFF;
					printf("%02x%02x%02x%02x\n\n",pData[38],pData[39],pData[40],pData[41]);
						
					unsigned int acktmp = *((unsigned int *)&pData[42]);
					acktmp = ntohl(acktmp);
					pData[38] = acktmp >> 24;
                                        pData[39] = (acktmp >> 16) & 0xFF;
                                        pData[40] = (acktmp >> 8) & 0xFF;
                                        pData[41] = acktmp & 0xFF;
					
					syntmp = acktmp + iphdr_len;
					pData[42] = syntmp >> 24;
                                        pData[43] = (syntmp >> 16) & 0xFF;
                                        pData[44] = (syntmp >> 8) & 0xFF;
                                        pData[45] = syntmp & 0xFF;
	
					for(j=0;j<4;j++){
                                                tcpchecksum[j]=server_ip[j];
                                                tcpchecksum[j+4]=client_ip[j];
                                        }
                                        tcpchecksum[8]='\x00';
          				tcpchecksum[9]='\x06';

                                        tcplen=tcphdr+iphdr_len;
                                        tcpchecksum[10]=ptr[1];
                                        tcpchecksum[11]=ptr[0];
                                        for(j=12;j<tcphdr+12;j++){
                                                tcpchecksum[j]=pData[j+21];
                                        }
                                        tcpchecksum[29]='\x00';
                                        tcpchecksum[30]='\x00';

                                        for(j=tcphdr+12;j<iphdr_len+tcphdr+12;j++){
                                                tcpchecksum[j]=pData[tcpdata+k];
                                                k++;
                                        }
                                        k=0;
                                        for(j=0;j<31+iphdr_len;j++){
                                                if(j==13) puts("");
                                                printf("%02x ",tcpchecksum[j]);
                                        }
                                        printf("\n");
                                        aa = checkcheck(tcpchecksum, tcphdr+iphdr_len+12);
                                        pData[checksum]=ptr[1];
                                        pData[checksum+1]=ptr[0];
						
					pData[flag]|=1;
					pData[flag]^=4;
					pcap_sendpacket(pPcap, pData, h.caplen);
				}
			}
		}
		
	}
	pcap_close(pPcap);        
	return 0;    
}
