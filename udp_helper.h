#include <netinet/udp.h>

class UDPhdr{
    struct udphdr* udp;
    public:
    UDPhdr(udphdr *udp);
    u_int16_t getsport();
    u_int16_t getdport();
    u_int16_t getlen();
    u_int16_t getsum();
    size_t getSize();
};
