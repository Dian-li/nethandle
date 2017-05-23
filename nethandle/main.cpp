#include <iostream>
#include <iomanip>
#include <csignal>
#include <sys/stat.h>
#include "stdio.h"
//#include "pcap_helper.h"
#include "tcp_helper.h"
#include <malloc.h>
using namespace std;
//#define FILENAME "test3.pcap"

int main(){
    char * filename = "test.pcap";
	printf("Running\n");
	ICapture *capture=0;

	capture = new FileCapture(filename);
	printf("开始处理文件：%s\n", filename);
//	if (!capture){
//		capture = new Capture;
//		printf("网络抓包开始\n");
//	}
	Manager manager(false);
    while (!capture->eof()){
        cout<<"1"<<endl;	
        pcap_header * hdr=(pcap_header *)malloc(sizeof(pcap_header));
       // pcap_pkthdr * hdr;
        const u_char* data=capture->next(hdr,filename); 
		manager.feed(data,hdr);
	}
	delete capture;
	printf("Finished\n");
    return 0;
}
