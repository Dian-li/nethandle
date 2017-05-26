#include "pcap_helper.h"
#include <csignal>
#include <fstream>
#include "stdlib.h"
#include <pcap.h>
#include <string.h>
#include <iostream>
#include <sys/time.h>
#include <malloc.h>
using namespace std;

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
int checkCPU() {//如果返回1为小端，返回0为大端 
    union w 
    {   
        int  a; 
        char b; 
    }c; 
 
    c.a = 1; 
    return (c.b == 1); 
}
void swe32(int32_t* value){
   ((*value & 0x000000FF) << 24) |((*value & 0x0000FF00) << 8) |  ((*value & 0x00FF0000) >> 8) | ((*value & 0xFF000000) >> 24);
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
    int32_t* ts = (int32_t*)malloc(sizeof(int32_t));
    int32_t* tus = (int32_t*)malloc(sizeof(int32_t));
    int32_t* copycaplen =(int32_t*)malloc(sizeof(int32_t)) ;
    int32_t* copylen = (int32_t*)malloc(sizeof(int32_t));
   
	in.read((char*)ts, 4);
    in.read((char*)tus,4);
    in.read((char*)copycaplen,4);
    in.read((char*)copylen,4);
    if(checkCPU()){
        swe32(ts);
        swe32(tus);
        swe32(copycaplen);
        swe32(copylen);
    }

    memcpy(&(h->ts.tv_sec),(char*)ts,4);
    memcpy(&(h->ts.tv_usec),(char*)tus,4);
    memcpy(&(h->caplen),(char*)copycaplen,4);
    memcpy(&(h->len),(char*)copylen,4);
    file_offset = in.tellg();
    in.seekg(file_offset, ios::beg);

	u_char* t = (u_char*)malloc(h->caplen);
	in.read((char *)t, h->caplen);
    file_offset = in.tellg();//修改偏移量
    in.close();
    delete(ts);
    delete(tus);
    delete(copycaplen);
    delete(copylen);
    //inverse((char *)t);
	return t;
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
