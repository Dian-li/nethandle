#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
//#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct my_ip
{
u_int8_t  ip_vhl; /* header length, version */
#define IP_V(ip)  (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)  ((ip)->ip_vhl & 0x0f)
u_int8_t  ip_tos; /* type of service */
u_int16_t  ip_len; /* total length */
u_int16_t  ip_id; /* identification */
u_int16_t  ip_off; /* fragment offset field */
#define IP_DF 0x4000  /* dont fragment flag */
#define IP_MF 0x2000  /* more fragments flag */
#define IP_OFFMASK 0x1fff  /* mask for fragmenting bits */
u_int8_t  ip_ttl; /* time to live */
u_int8_t  ip_p;  /* protocol */
u_int16_t  ip_sum; /* checksum */
struct in_addr ip_src,ip_dst; /* source and dest address */
};

class IPhdr{
    my_ip* iphdr;
public:
    IPhdr(my_ip * iphdr);
     size_t getHeadLength();
    u_int8_t getProtocol();//IPPROTO_TCP or IPPROTO_UDP
    size_t getVersion();
    u_short getLength();
    size_t getSize();
    char * getIPSrc();
    char * getIPDst();
    virtual ~IPhdr(){}


};
