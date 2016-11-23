#include "getmac.h"

#include <WinSock2.h>
#include <Iphlpapi.h>

#pragma comment(lib, "Iphlpapi.lib")

void getmac(const char *l_name, unsigned char rt[6])
{

	//PIP_ADAPTER_INFO�ṹ��ָ��洢����������Ϣ
	PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
	//�õ��ṹ���С,����GetAdaptersInfo����
	unsigned long stSize = sizeof(IP_ADAPTER_INFO);
	//����GetAdaptersInfo����,���pIpAdapterInfoָ�����;����stSize��������һ��������Ҳ��һ�������
	int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
	if (ERROR_BUFFER_OVERFLOW == nRel)
	{
		//����������ص���ERROR_BUFFER_OVERFLOW
		//��˵��GetAdaptersInfo�������ݵ��ڴ�ռ䲻��,ͬʱ�䴫��stSize,��ʾ��Ҫ�Ŀռ��С
		//��Ҳ��˵��ΪʲôstSize����һ��������Ҳ��һ�������
		//�ͷ�ԭ�����ڴ�ռ�
		delete pIpAdapterInfo;
		//���������ڴ�ռ������洢����������Ϣ
		pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
		//�ٴε���GetAdaptersInfo����,���pIpAdapterInfoָ�����
		nRel=GetAdaptersInfo(pIpAdapterInfo, &stSize);
	}
	if (ERROR_SUCCESS == nRel)
	{
		//���������Ϣ
		auto t = pIpAdapterInfo;
		while (pIpAdapterInfo)
		{
			if (strstr(l_name, pIpAdapterInfo->AdapterName))
			{
				rt[0] = pIpAdapterInfo->Address[0];
				rt[1] = pIpAdapterInfo->Address[1];
				rt[2] = pIpAdapterInfo->Address[2];
				rt[3] = pIpAdapterInfo->Address[3];
				rt[4] = pIpAdapterInfo->Address[4];
				rt[5] = pIpAdapterInfo->Address[5];
				break;
			}
			pIpAdapterInfo = pIpAdapterInfo->Next;
		}
		pIpAdapterInfo = t;

	}
	//�ͷ��ڴ�ռ�
	if (pIpAdapterInfo)
	{
		delete pIpAdapterInfo;
	}
}

//void output(PIP_ADAPTER_INFO pIpAdapterInfo)
//{
//	//�����ж�����,���ͨ��ѭ��ȥ�ж�
//	while (pIpAdapterInfo)
//	{
//		cout << "�������ƣ�" << pIpAdapterInfo->AdapterName << endl;
//		cout << "����������" << pIpAdapterInfo->Description << endl;
//		cout << "����MAC��ַ��" << pIpAdapterInfo->Address;
//		for (UINT i = 0; i < pIpAdapterInfo->AddressLength; i++)
//			if (i == pIpAdapterInfo->AddressLength - 1)
//			{
//				printf("%02x\n", pIpAdapterInfo->Address[i]);
//			}
//			else
//			{
//				printf("%02x-", pIpAdapterInfo->Address[i]);
//			}
//		cout << "����IP��ַ���£�" << endl;
//		//���������ж�IP,���ͨ��ѭ��ȥ�ж�
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