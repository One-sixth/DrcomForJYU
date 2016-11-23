#include "getmac.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>

using namespace std;

void getmac(const char *l_name, unsigned char rt[6])
{
	ifreq ifr;
	int sock = 0;
	memset(rt, 0, 6);

	sock = socket(AF_INET,SOCK_STREAM, 0);
	if(sock < 0)
		return;

	strcpy(ifr.ifr_name, l_name);
	if(ioctl(sock,SIOCGIFHWADDR, &ifr) < 0)
		return;

	for(int i = 0; i < 6; i++)
		rt[i] = ifr.ifr_hwaddr.sa_data[i];
}
