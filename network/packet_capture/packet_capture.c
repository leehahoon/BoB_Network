#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

int main(){        
	char errbuf[PCAP_ERRBUF_SIZE];        
	char * Device;        
	Device = pcap_lookupdev(errbuf);        
	printf("%s\n",Device);        
	pcap_t * pPcap;            
	pPcap = pcap_open_live(Device,1500, 1, 0, errbuf); 
	
	char *packet[38];
	char *des_port;
	char *a;
	char *src_port;
	int i; 
	long port1, port2;     
	if(NULL == pPcap)        {            
		printf("%s\n",errbuf);            
		return 0;        
	}      
  
	const u_char * pData;        
	struct pcap_pkthdr h;
	while(1){        
		pData = pcap_next(pPcap, &h);
	        
		for(i = 0; i <39; ++i)        {            
			packet[i]=*(pData+i);
		}      
		
		if(!(packet[12]==8 && packet[13]==0)){
			printf("Not IP Type!\n\n");
			continue;
		}
		printf("Des Mac Addr ==> ");
		for(i=0;i<6;i++)
			printf("%02x:",packet[i]);
		printf("\n");	
	
		printf("Src Mac Addr ==> ");
		for(i=6;i<12;i++)
			printf("%02x:",packet[i]);
		printf("\n");
		
		printf("Des Ip Addr ==> ");
		for(i=30;i<34;i++)
			printf("%d.",packet[i]);
		printf("\n");
	
		printf("Src Ip Addr ==> ");
		for(i=26;i<30;i++)
			printf("%d.",packet[i]);
		printf("\n");
		
		printf("Des Port Number ==> ");
		sprintf(des_port, "0x%02x%02x", packet[36],packet[37]);
		port1 = strtoul(des_port, NULL, 16);
		printf("%d\n",port1);
		
		printf("Src Port Number ==> ");
		sprintf(src_port, "0x%02x%02x", packet[34],packet[35]);
		port2 = strtol(src_port, NULL, 16);
		printf("%d\n",port2);
		printf("\n\n");
		//sleep(1);
	}
	pcap_close(pPcap);        
	return 0;    
}
