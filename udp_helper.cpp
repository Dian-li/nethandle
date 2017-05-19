#include "udp_helper.h"

UDPhdr::UDPhdr(udphdr * hdr){
    udp = hdr;
}

u_int16_t UDPhdr::getsport(){
    return udp->uh_sport;
}

u_int16_t UDPhdr::getdport(){
    return udp->uh_dport;
}

u_int16_t UDPhdr::getlen(){
    return udp->uh_ulen;
}

u_int16_t UDPhdr::getsum(){
    return udp->uh_sum;
}
