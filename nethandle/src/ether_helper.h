#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class Etherhdr{

    private:
         ether_header * etherhdr;
    public:
         Etherhdr(ether_header * hdr);
         char * getDhost();
         char * getShost();
         size_t getSize();
         size_t getType();
         virtual  ~Etherhdr(){}


};
