objects=main.o tcp_helper.o pcap_helper.o ether_helper.o ip_helper.o udp_helper.o
main:$(objects) 
	g++ -Wall -I /usr/local/libcap-1.8.1/include/ \
		-I /usr/local/libxml2-2.9.4/include/libxml2/ \
		-L /usr/local/libcap-1.8.1/lib/ \
		-L /usr/local/libxml2-2.9.4/lib/ \
		-g -o main $(objects) -lpcap -lxml2

main.o:main.cpp tcp_helper.h
	g++ -c -g -Wall main.cpp
tcp_helper.o:tcp_helper.cpp tcp_helper.h
	g++ -c -g -Wall tcp_helper.cpp
pcap_helper.o:pcap_helper.cpp pcap_helper.h
	g++ -c -g -Wall pcap_helper.cpp
ether_helper.o:ether_helper.cpp ether_helper.h
	g++ -c -g -Wall ether_helper.cpp
ip_helper.o:ip_helper.cpp ip_helper.h
	g++ -c -g -Wall ip_helper.cpp
udp_helper.o:udp_helper.cpp udp_helper.h
	g++ -c -g -Wall udp_helper.cpp
.PHONY:clean

clean:  
	rm -rf *.o main
