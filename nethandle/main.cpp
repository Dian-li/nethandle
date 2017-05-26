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
    char * filename = "csdn.pcap";
	printf("Running\n");
	ICapture *capture=0;

	capture = new FileCapture(filename);
	printf("开始处理文件：%s\n", filename);
	Manager manager(false);
    while (!capture->eof()){
       
        pcap_header * hdr=(pcap_header *)malloc(sizeof(pcap_header));
       
        const u_char* data=capture->next(hdr,filename); 
		manager.feed(data,hdr);
	}
	delete capture;
	printf("Finished\n");
    return 0;
}
