#include <string>
#include <iostream>
#include <cstring>
#include <netinet/tcp.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
//#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "pcap_helper.h"
using namespace std;

typedef unsigned int uint;
typedef unsigned short ushort;
typedef unsigned char uchar;

class TCPhdr{
    struct tcphdr * tcp;
    public:
    TCPhdr(tcphdr * tcp);
    //size_t getSize();
    u_int16_t getsport();
    u_int16_t getdport();
    u_int16_t getHeadLength();
    
};


class Manager{
	unsigned int id;
    char * nowip;
    bool check;
	
public:
	Manager();	
    Manager(bool check);
	int feed(const uchar *data, pcap_header *packet);

};
