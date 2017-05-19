#include "pcap_helper.h"
#include <csignal>
#include <fstream>
#include "stdlib.h"
#include <pcap.h>
#include <string.h>
#include <iostream>
#include <sys/time.h>
#include <malloc.h>
//#include "tcp_helper.h"
using namespace std;
//字符串逆置 
void inverse(char *str){
    char *p1 = str;
    char *p2 = str + strlen(str) - 1;
    while (p1 < p2) {
        char tmp = *p1;
        *p1 = *p2;
        *p2 = tmp;
        p1++;
        p2--;
    }
}
FileCapture::FileCapture(char * file){
    in.open(file, ios::binary);
	if (!in){
		cerr << file << " can not open!" << endl;
		exit(10);
	}
    in.seekg(0, ios::beg);
    int l = in.tellg();
	in.seekg(0, ios::end);
	int m = in.tellg();
    file_length = m-l;
    in.seekg(0, ios::beg);

    in.read((char *)&header, sizeof(header));
   // cout<<"header"<<header<<endl;
    file_offset = in.tellg();
    in.close();
}

bool FileCapture::eof(){
	return file_offset>=file_length;
}

const uchar * FileCapture::next(pcap_header * h,char * file){
    
    in.open(file, ios::binary|ios::in);
   
	if (!in){
		cerr << file << " can not open!" << endl;
		exit(10);
	}
    in.seekg(file_offset, ios::beg);
    printf("pcap头部长度：\n");
    char * ts = new char[4];
    char * tus = new char[4];
    char * copycaplen = new char[4];
    char * copylen = new char[4];
   // memset(ts,0,4);
   // memset(tus,0,4);
   // memset(copycaplen,0,4);
   // memset(copylen,0,4);
	in.read(ts, 4);
    in.read(tus,4);
    in.read(copycaplen,4);
    in.read(copylen,4);
    for(int i=0;i<4;i++){
        printf("%02x %02x %02x %02x\n",ts[i],tus[i],copycaplen[i],copylen[i]);
    }
    inverse(ts);
    inverse(tus);
    inverse(copycaplen);
    inverse(copylen);
    //h = (pcap_pkthdr *)malloc(sizeof(pcap_pkthdr)); 
    //__time_t  t_ts = (__time_t)malloc(sizeof(__time_t));
   // __suseconds_t  t_tus = (__suseconds_t)malloc(sizeof(__suseconds_t));
   // bpf_u_int32  t_copycaplen = (bpf_u_int32)malloc(sizeof(bpf_u_int32));
   // bpf_u_int32  t_copylen = (bpf_u_int32)malloc(sizeof(bpf_u_int32));

   // strcpy((char *)t_ts,ts);
   // strcpy((char *)t_tus,tus);
   // strcpy((char *)t_copycaplen,copycaplen);
   // strcpy((char *)t_copylen,copylen);
   // h->ts.tv_sec = (__time_t)t_ts;
   // h->ts.tv_usec = (__suseconds_t)t_tus;
   // h->caplen = (bpf_u_int32)t_copycaplen;
   // h->len = (bpf_u_int32)t_copylen; 
    memcpy(&(h->ts.tv_sec),ts,4);
    memcpy(&(h->ts.tv_usec),tus,4);
    memcpy(&(h->caplen),copycaplen,4);
    memcpy(&(h->len),copylen,4);
    file_offset = in.tellg();
    in.seekg(file_offset, ios::beg);

	u_char* t = (u_char*)malloc(h->caplen);
	in.read((char *)t, h->caplen);
    file_offset = in.tellg();//修改偏移量
    in.close();
    //inverse((char *)t);
	return t;//reverse
}

//Capture* Capture::instance=0;
//bool Capture::running=false;
//Capture::Capture(){
//	*errBuf = 0; // 减少错误信息
//	running = true;
//	if (instance){
//		*this = *instance;
//		return;
//	}
//	devStr= pcap_lookupdev(errBuf);
//	if(!devStr){
//	  error();
//	}
//	device = pcap_open_live(devStr, 65535, 1, 0, errBuf);
//	if(!device)  {
//		error();
//	}
//	setfilter("port 80");
//
//	instance = this;
//	signal(SIGINT, sig_handler);
//}

//void Capture::sig_handler(int para){
//	printf("[!]SIGINT catch, pargrom will exit.\n");
//	running = false;
//}
//
//void Capture::error(){
//	printf("error: %s\n", errBuf);
//	exit(1);
//}
//
//void Capture::setfilter(string s){
//	  pcap_compile(device, &filter, s.c_str(), 1, 0);
//	  pcap_setfilter(device, &filter);
//}
//
//const uchar *Capture::next(pcap_pkthdr *packet){
//		return  ::pcap_next(device, packet);
//}
//
//Capture::~Capture(){
//	pcap_close(device);
//}
//
//bool Capture::eof(){
//	return !running;
//}
