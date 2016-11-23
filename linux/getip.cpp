#include "getip.h"
     
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <string>
#include <algorithm>

#include <fstream>

using namespace std;

static void IpTextToBytes(string ipText, unsigned char ip[4])
{
	size_t p = -1;
	for (size_t i = 0; i < 4; i++)
		ip[i] = (unsigned char)stoul(ipText = ipText.substr(p + 1), &p);
}

void getip(const char *l_name, unsigned char rt[4])
{
	memset(rt, 0, 4);
	fstream f;
	f.open("config.txt");
	if (f.is_open())
	{
		string ip;
		f >> ip;
		if(!ip.empty())
		{
			IpTextToBytes(ip.c_str(), rt);
		}
	}
	
//	string s = l_name;
//	transform(s.begin(), s.end(), s.begin(), ::tolower);
//	ifaddrs *ifAddrStruct = nullptr;
//	void *tmpAddrPtr = nullptr;
//
//	getifaddrs(&ifAddrStruct);
//	memset(rt, 0, 4);
//	
//	while (ifAddrStruct != nullptr)
//	{
//		string ifname = ifAddrStruct->ifa_name;
//		transform(ifname.begin(), ifname.end(), ifname.begin(), ::tolower);
//		if(ifname == s)
//		{
//			//if (ifAddrStruct->ifa_addr->sa_family == AF_INET)
//			{
//				char host[NI_MAXHOST] = {0};
//				getnameinfo(ifAddrStruct->ifa_addr, sizeof(sockaddr_in), host, NI_MAXHOST, 0, NI_NUMERICHOST);
//				
//				tmpAddrPtr = &((sockaddr_in *)ifAddrStruct->ifa_addr)->sin_addr;
//				char addressBuffer[INET_ADDRSTRLEN];
//				inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
//				IpTextToBytes(/*addressBuffer*/host, rt);
//			}
//			break;
//		}
//		ifAddrStruct = ifAddrStruct->ifa_next;
//	}
}
