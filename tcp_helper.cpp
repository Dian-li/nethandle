#include "tcp_helper.h"
#include <arpa/inet.h>
#include <iostream>
#include <string>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <pcap.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <malloc.h>
#include "ether_helper.h"
#include "ip_helper.h"
Manager::Manager():id(0){}

TCPhdr::TCPhdr(tcphdr * hdr){
    tcp = hdr;
}
u_int16_t TCPhdr::getsport(){// source port
    return tcp->source;
}
u_int16_t TCPhdr::getdport(){
    return tcp->dest;
}
u_int16_t TCPhdr::getHeadLength(){
    return (tcp->doff)*4;
}
int Manager::feed(const uchar *data, pcap_header *packet){
	id++;
    //int len = packet->len;
	printf("[*]Manager::feed 分析第%d个包... \n",id);
    printf("Packet length: %d\n", packet->len);
    //string time_str(ctime((const time_t *)&packet->ts.tv_sec));
    //time_str.erase(time_str.length()-1);
    //printf("Recieved time: %s\n",time_str.c_str() );
    ether_header * ether = (ether_header*)malloc(sizeof(ether_header));
    memcpy(ether,data,sizeof(ether_header));

	Etherhdr *etherhdr = new Etherhdr(ether);
	data += etherhdr->getSize();
	if ((etherhdr->getType()) != ETHERTYPE_IP){
		printf("[!] not an ip package!\n");
	//	return 1;
	}
    printf("目的mac地址:%s\n",etherhdr->getDhost());
    printf("源mac地址:%s\n",etherhdr->getShost());
    my_ip * ip = (my_ip*)malloc(sizeof(my_ip));
    memcpy(ip,data,sizeof(my_ip));

	IPhdr *iphdr = new IPhdr(ip);
   	data += iphdr->getHeadLength();
	if (iphdr->getVersion() == 4){
		printf( "IP protocol id %d !\n", iphdr->getVersion());
	}
    printf("目的IP地址:%s\n",iphdr->getIPDst());
    printf("源IP地址:%s\n",iphdr->getIPSrc());
	tcphdr * newtcphdr = (tcphdr *)malloc(sizeof(tcphdr));
    memcpy(newtcphdr,data,sizeof(tcphdr));
    
    TCPhdr *tcp = new TCPhdr(newtcphdr);
    printf("头部长度：%d\n",tcp->getHeadLength());
    printf("源端口%d\n",tcp->getsport());
    printf("目的端口%hd\n",tcp->getsport());

    data += tcp->getHeadLength();

    u_char * tcpContent = (u_char*)data;
    for(int i=0;i<strlen((const char *)tcpContent);i++){
        printf(" %02x", tcpContent[i]);  
        if( (i + 1) % 16 == 0 ) {  
            printf("\n");  
        }  

    }
	printf("分析第%d个包结束. \n\n",id);
	return 0;
}



string int2char(in_addr a){
	return string(inet_ntoa(a));
}// test
