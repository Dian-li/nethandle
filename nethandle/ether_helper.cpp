#include "ether_helper.h"

Etherhdr::Etherhdr(ether_header* hdr){
    etherhdr = hdr;
}

char *Etherhdr::getDhost(){
    return ether_ntoa((ether_addr *)etherhdr->ether_dhost);
}

char *Etherhdr::getShost(){
     return ether_ntoa((ether_addr *)etherhdr->ether_shost);
}

size_t Etherhdr::getSize(){
        return sizeof(ether_header);
}
size_t Etherhdr::getType(){
     return ntohs(etherhdr->ether_type);
} 

