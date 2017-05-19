#include <fstream>
#include <iostream>
#include <pcap.h>
#include <netinet/in.h>
#include <stddef.h>
//#include "tcp_helper.h"
using namespace std;

typedef u_int16_t _Int16;
typedef	bpf_u_int32  _Int32;
typedef unsigned char uchar;
// Pcap文件头
struct __file_header
{
	_Int32	iMagic;
	_Int16	iMaVersion;
	_Int16	iMiVersion;
	_Int32	iTimezone;
	_Int32	iSigFlags;
	_Int32	iSnapLen;
	_Int32	iLinkType;
};
struct timevalnew{
    bpf_u_int32 tv_sec;
    bpf_u_int32 tv_usec;
};
//pcap header
struct pcap_header{
    struct timevalnew ts;
    bpf_u_int32 caplen;
    bpf_u_int32 len;
};
class ICapture{
public:
	virtual bool eof() = 0;
	virtual const uchar * next(pcap_header * hdr,char * filename) = 0;
	virtual ~ICapture(){}
};

class FileCapture:public ICapture{
	__file_header header;
    
	struct pcap_t;
	ifstream in;
	int file_offset;
    int file_length;
public:
	FileCapture(char * file);
	const uchar * next(pcap_header * hdr,char * filename);
	bool eof();
	virtual  ~FileCapture(){}
};

//class Capture:public ICapture{  //todo 处理ctrl+c，正常退出
//	char errBuf[PCAP_ERRBUF_SIZE], * devStr;
//	pcap_t * device;
//	 struct bpf_program filter;
//	void error();
//	static void sig_handler(int sig);
//	static Capture* instance;
//	static bool running;
//	//处理ctrl+c，正常退出
//public:
//	 Capture();
//	const uchar *next(pcap_pkthdr *);
//	void setfilter(string s);
//	bool eof();
//	 ~Capture();
//};

