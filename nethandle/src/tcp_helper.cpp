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
#include <libxml/parser.h>
#include <libxml/tree.h>

#define FILE_NAME "packet.xml"
using namespace std;
Manager::Manager():id(0){}
Manager::Manager(bool c){
    check = c;
}
TCPhdr::TCPhdr(tcphdr * hdr){
    tcp = hdr;
}
u_int16_t TCPhdr::getsport(){// source port
    return ntohs(tcp->source);
}
u_int16_t TCPhdr::getdport(){
    return ntohs(tcp->dest);
}
u_int16_t TCPhdr::getHeadLength(){
    return (tcp->doff)*4;
}
int Manager::feed(const uchar *data, pcap_header *packet){
    id++;

    printf("[*]Manager::feed 分析第%d个包... \n",id);
    printf("Packet length: %d\n", packet->len);
    //string time_str(ctime((const time_t *)&packet->ts.tv_sec));
    //time_str.erase(time_str.length()-1);
    //printf("Recieved time: %s\n",time_str.c_str() );
    ether_header * ether = (ether_header*)malloc(sizeof(ether_header));
    memcpy(ether,data,sizeof(ether_header));

    Etherhdr *etherhdr = new Etherhdr(ether);
    data += etherhdr->getSize();
    if ((etherhdr->getType()) == ETHERTYPE_IP){
      
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
        if(iphdr->getProtocol()==IPPROTO_TCP){//tcp
            tcphdr * newtcphdr = (tcphdr *)malloc(sizeof(tcphdr));
            memcpy(newtcphdr,data,sizeof(tcphdr));
            if(check==false){
                nowip = iphdr->getIPSrc();
                check = true;
                // printf("nowip:%s\n",Manager::nowip);
            }
            TCPhdr *tcp = new TCPhdr(newtcphdr);
            printf("头部长度：%d\n",tcp->getHeadLength());
            printf("源端口%d\n",tcp->getsport());
            printf("目的端口%d\n",tcp->getdport());

            data += tcp->getHeadLength();
            u_char * tcpContent = (u_char*)data;
            char temp[2];
            //char * content="";
            int value=0;
            int contentlen = strlen((const char *)tcpContent);
            string content="";
            //strcpy(content,"");
            string str;
            if(contentlen>0){
                for(int i=0;i<contentlen;i++){
                    sprintf(temp,"%02x",tcpContent[i]);          
                    sscanf(temp,"%02x",&value);           
                    if(value>=0x20 && value<=0x7E){
                        // sprintf(temp2,"%.1s",value);
                        temp[0]=tcpContent[i];
                        temp[1]='\0';
                        str = temp;
                        content += str;
                    }else{
                        // char * exch ;
                        //sscanf(&value,"%s",exch); 
                        content += "\\x";
                        str = (char *) temp;
                        content += str;
                    }
                  

                }
            }


            //写入xml中
            xmlDocPtr doc = NULL;
            xmlNodePtr root_node =NULL,child=NULL,node=NULL;
            doc = xmlReadFile(FILE_NAME,NULL,256);
            if(doc==NULL){
                doc = xmlNewDoc(BAD_CAST"1.0");
                root_node = xmlNewNode(NULL,BAD_CAST"packet");
                xmlDocSetRootElement(doc, root_node);

            }
            //doc = xmlNewDoc(BAD_CAST"1.0");
            root_node = xmlDocGetRootElement(doc);
            char* childname = "";
            char* childip = "";
            int childport ;
            if(nowip.compare(iphdr->getIPSrc())==0){
                childname = "send";
                // childip = iphdr->getIPSrc();
               // childport = tcpget
            }else{
                childname = "rev";
                // childip = iphdr->getIPSrc();
            }
            childip = iphdr->getIPSrc();
            childport = tcp->getsport();
            char childports[16];
            sprintf(childports,"%d",childport);//change to char *
            child = xmlNewChild(root_node,NULL,BAD_CAST(childname),NULL);
            xmlNewProp(child, BAD_CAST"ip" , BAD_CAST(childip));
            xmlNewProp(child, BAD_CAST"port" , BAD_CAST(childports));
            node =xmlNewCDataBlock(doc,BAD_CAST(content.c_str()),contentlen+1);
            xmlAddChild(child,node);
            xmlSaveFormatFileEnc(FILE_NAME, doc, "UTF-8", 1);
            xmlFreeDoc(doc);

        }
    }
    printf("分析第%d个包结束. \n\n",id);
    return 0;
}



string int2char(in_addr a){
    return string(inet_ntoa(a));
}// test
