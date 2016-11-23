#include "getip.h"

#include <WinSock2.h>
#include <Iphlpapi.h>

#include <string>
using namespace std;

#pragma comment(lib, "Iphlpapi.lib")

static void IpTextToBytes(string ipText, unsigned char ip[4])
{
	size_t p = -1;
	for (size_t i = 0; i < 4; i++)
		ip[i] = (unsigned char)stoul(ipText = ipText.substr(p + 1), &p);
}

void getip(const char *l_name, unsigned char rt[4])
{

	//PIP_ADAPTER_INFO结构体指针存储本机网卡信息
	PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
	//得到结构体大小,用于GetAdaptersInfo参数
	unsigned long stSize = sizeof(IP_ADAPTER_INFO);
	//调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量;其中stSize参数既是一个输入量也是一个输出量
	int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
	if (ERROR_BUFFER_OVERFLOW == nRel)
	{
		//如果函数返回的是ERROR_BUFFER_OVERFLOW
		//则说明GetAdaptersInfo参数传递的内存空间不够,同时其传出stSize,表示需要的空间大小
		//这也是说明为什么stSize既是一个输入量也是一个输出量
		//释放原来的内存空间
		delete pIpAdapterInfo;
		//重新申请内存空间用来存储所有网卡信息
		pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
		//再次调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量
		nRel=GetAdaptersInfo(pIpAdapterInfo, &stSize);
	}
	if (ERROR_SUCCESS == nRel)
	{
		//输出网卡信息
		auto t = pIpAdapterInfo;
		while (pIpAdapterInfo)
		{
			if (strstr(l_name, pIpAdapterInfo->AdapterName))
			{
				if (pIpAdapterInfo->DhcpEnabled)
				{
					memset(rt, 0, 4);
					return;
				}
				IP_ADDR_STRING *pIpAddrString =&(pIpAdapterInfo->IpAddressList);
				IpTextToBytes(pIpAddrString->IpAddress.String, rt);
				break;
			}
			pIpAdapterInfo = pIpAdapterInfo->Next;
		}
		pIpAdapterInfo = t;

	}
	//释放内存空间
	if (pIpAdapterInfo)
	{
		delete pIpAdapterInfo;
	}
}


//void output(PIP_ADAPTER_INFO pIpAdapterInfo)
//{
//	//可能有多网卡,因此通过循环去判断
//	while (pIpAdapterInfo)
//	{
//		cout << "网卡名称：" << pIpAdapterInfo->AdapterName << endl;
//		cout << "网卡描述：" << pIpAdapterInfo->Description << endl;
//		cout << "网卡MAC地址：" << pIpAdapterInfo->Address;
//		for (UINT i = 0; i < pIpAdapterInfo->AddressLength; i++)
//			if (i == pIpAdapterInfo->AddressLength - 1)
//			{
//				printf("%02x\n", pIpAdapterInfo->Address[i]);
//			}
//			else
//			{
//				printf("%02x-", pIpAdapterInfo->Address[i]);
//			}
//		cout << "网卡IP地址如下：" << endl;
//		//可能网卡有多IP,因此通过循环去判断
//		IP_ADDR_STRING *pIpAddrString =&(pIpAdapterInfo->IpAddressList);
//		do
//		{
//			cout << pIpAddrString->IpAddress.String << endl;
//			pIpAddrString=pIpAddrString->Next;
//		} while (pIpAddrString);
//		pIpAdapterInfo = pIpAdapterInfo->Next;
//		cout << "*****************************************************" << endl;
//	}
//	return;
//}