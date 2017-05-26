#include "ip_helper.h"



IPhdr::IPhdr(my_ip* hdr){
    iphdr= hdr;
}
size_t IPhdr::getHeadLength(){
        return IP_HL(iphdr)*4;
    }
u_int8_t IPhdr::getProtocol(){//IPPROTO_TCP or IPPROTO_UDP
       // return ntohs(iphdr->ip_p);
        return iphdr->ip_p;
    }
size_t IPhdr::getVersion(){
        return IP_V(iphdr);
    }
u_short IPhdr::getLength(){
        return iphdr->ip_len;
    }
size_t IPhdr::getSize(){
        return sizeof(my_ip);
    }
char* IPhdr::getIPSrc(){
        return inet_ntoa(iphdr->ip_src);
    }
char *IPhdr::getIPDst(){
        return inet_ntoa(iphdr->ip_dst);
    }

