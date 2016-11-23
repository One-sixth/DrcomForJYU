#include "DrcomForJY.h"
#define WIN32
#include <pcap.h>
#include "getmac.h"
#include "getip.h"
#include "EAPOL.h"
#include "md5.h"


#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "wpcap.lib")

#pragma warning(disable:4996)

DrcomForJY::DrcomForJY()
{
}

DrcomForJY::~DrcomForJY()
{
	if (pcapDev)
		pcap_close((pcap *)pcapDev), pcapDev = nullptr;
}

bool DrcomForJY::ListDev(vector<string> &devNameList, vector<string> &descriptionList)
{
	devList.clear();
	devDescriptionList.clear();

	pcap_if_t *alldevs;
	pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		error = string() + "无法寻找网卡，pcap_findalldevs，" + errbuf;
		return false;
	}

	for (d=alldevs; d; d=d->next)
	{
		devList.push_back(d->name);
		devDescriptionList.push_back(d->description ? d->description : "(No description available)");
	}
	pcap_freealldevs(alldevs);

	devNameList = devList;
	descriptionList = devDescriptionList;

	error = "";
	return true;
}

bool DrcomForJY::SelectDev(string devName)
{
	if (pcapDev)
		pcap_close((pcap *)pcapDev), pcapDev = nullptr;
	char errbuf[PCAP_ERRBUF_SIZE];
	if ((pcapDev = pcap_open_live(devName.c_str(),	// name of the device
								  65536,			// portion of the packet to capture. 
													// 65536 grants that the whole packet will be captured on all the MACs.
								  1,				// promiscuous mode (nonzero means promiscuous)
								  listenTime,		// read timeout
								  errbuf			// error buffer
	)) == NULL)
	{
		error = "无法打开网卡。" + devName + " 不被 WinPcap 支持";
		return false;
	}

	bpf_program fcode;
	//使用过滤器，去掉其他多余的包
	char packet_filter[] = "not arp and not tcp and not udp and not icmp";
	unsigned int netmask = 0xffffff;

	if (pcap_compile((pcap_t *)pcapDev, &fcode, packet_filter, 1, netmask) <0)
	{
		error = "无法编译过滤器 pcap_compile 出错";
		return false;
	}

	//set the filter
	if (pcap_setfilter((pcap_t *)pcapDev, &fcode)<0)
	{
		error  = "无法设置过滤器 pcap_setfilter 出错";
		return false;
	}

	//得到本机MAC地址
	getmac(devName.c_str(), (unsigned char *)clientMac);
	getip(devName.c_str(), (unsigned char *)clientIp);
	if (!memcmp(clientIp, "\x00\x00\x00\x00", 4))
	{
		error = "无法得到网卡IP地址，请设置网卡为静态IP";
		return false;
	}

	error = "";
	return true;
}

void DrcomForJY::SetUserName(string userName)
{
	this->userName = userName;
}

void DrcomForJY::SetPassword(string password)
{
	this->password = password;
}

void DrcomForJY::Login()
{
	char id[1];
	char passwordMd5[16];

	bool b = LogoffEapOL();
	if (!b)	return;
	b = StartEapOL();
	if (!b)	return;
	b = WaitingRequestUserName(id);
	if (!b)	return;
	b = ResponseUserName(id, userName.c_str());
	if (!b)	return;
	b = WaitingRequestPasswork(id, passwordMd5);
	if (!b)	return;
	b = ResponsePasswork(id, userName.c_str(), password.c_str(), passwordMd5);
	if (!b)	return;
	b = WaitingSuccess();
	if (!b)	return;
	return;
}

void DrcomForJY::Logoff()
{
	LogoffEapOL();
}

string DrcomForJY::GetError()
{
	return error;
}

void DrcomForJY::SetOverTime(unsigned int ms)
{
	overTime = ms;
}

bool DrcomForJY::LogoffEapOL()
{
	if (!pcapDev)
	{
		error = "未选择网卡";
		return false;
	}
	
	EAPOL ea;
	char packet[EAPOL::PACKET_MAX_SIZE] ={0};
	ea.SetDst(packet, NearestMac);
	ea.SetSrc(packet, clientMac);
	ea.SetEapol(packet, ea.Eapol_Type_Logoff);
	pcap_sendpacket((pcap_t *)pcapDev, (unsigned char *)packet, ea.GetPacketSize(packet));

	//Logoff后需要吃掉后面一个Failure包，这里直接清空队列算了
	while (true)
	{
		struct pcap_pkthdr *header;
		const unsigned char *pkt_data;

		int res = pcap_next_ex((pcap_t *)pcapDev, &header, &pkt_data);
		if (res == -1)		//出错
			throw;
		else if (res == 0)	//超时
			break;
	}
	return true;
}

bool DrcomForJY::StartEapOL()
{
	if (!pcapDev)
	{
		error = "未选择网卡";
		return false;
	}

	EAPOL ea;
	char packet[EAPOL::PACKET_MAX_SIZE] ={0};
	ea.SetDst(packet, NearestMac);
	ea.SetSrc(packet, clientMac);
	ea.SetEapol(packet, ea.Eapol_Type_Start);
	pcap_sendpacket((pcap_t *)pcapDev, (unsigned char *)packet, ea.GetPacketSize(packet));
	return true;
}

bool DrcomForJY::WaitingRequestUserName(char id[1])
{
	overedTime = overTime;	//重置超时时间
	EAPOL ea;
	char packet[EAPOL::PACKET_MAX_SIZE] ={0};
	while (true)
	{
		struct pcap_pkthdr *header;
		const unsigned char *pkt_data;

		int res = pcap_next_ex((pcap_t *)pcapDev, &header, &pkt_data);
		if (res == -1)		//出错
		{
			error = "pcap接收包出错";
			return false;
		}
		else if (res == 0)	//超时
		{
			if (overedTime <= 0)
			{
				error = "服务器无响应";
				return false;
			}
			overedTime -= listenTime;
			continue;
		}

		//收到一个包
		memcpy_s(&packet, sizeof(packet), pkt_data, sizeof(packet) < header->len ? sizeof(packet) : header->len);

		char dstMac[6];
		ea.GetDst(packet, dstMac);

		if (memcmp(dstMac, clientMac, 6) == 0)		//判断是否是发到本机的数据包
		{
			if (ea.GetEap(packet))					//是否为Eap协议的包
			{
				if (!memcmp(ea.GetEap(packet)->code, ea.Eap_Code_Request, sizeof EAPOL::Eap::code) &&
					!memcmp(ea.GetEap(packet)->type, ea.Eap_Type_Identity, sizeof EAPOL::Eap::type))			//是否为Request的请求包，是否为Identity要求认证的包
				{
					memcpy(id, ea.GetEap(packet)->id, sizeof EAPOL::Eap::id);
					error = "";
					return true;
				}
				else if (!memcmp(ea.GetEap(packet)->code, ea.Eap_Code_Failure, sizeof EAPOL::Eap::code))
				{
					error = "服务器拒绝认证";
					return false;
				}
				//来到这里，一般是收错包了，继续接收包
			}
		}
	}
	error = "未知错误";
	return false;
}

bool DrcomForJY::ResponseUserName(char id[1], const char *userName)
{
	if (!pcapDev)
	{
		error = "未选择网卡";
		return false;
	}
	//不知什么用，跟在userName后面
	//unknow的最后4个字节为本机IP地址
	char unknow[] ={
		0x00, 0x44, 0x61, 0x00, 0x00, 0xff, 0xff, 0xff,
		0xff
	};

	//设置IP
	memcpy(unknow + sizeof(unknow) - 4, clientIp, 4);

	//生成用户id
	char *userNameAfter = new char[strlen(userName) + sizeof unknow];
	strcpy(userNameAfter, userName);
	memcpy(userNameAfter + strlen(userName), unknow, sizeof unknow);

	//制作包
	EAPOL ea;
	char packet[EAPOL::PACKET_MAX_SIZE] ={0};
	ea.SetDst(packet, NearestMac);
	ea.SetSrc(packet, clientMac);
	ea.SetEapol(packet, ea.Eapol_Type_Eap);
	ea.SetEap(packet, ea.Eap_Code_Response, id, ea.Eap_Type_Identity);
	ea.SetEapExtraData(packet, ea.Eap_Type_Identity, userNameAfter, strlen(userName) + sizeof unknow);
	delete userNameAfter;
	pcap_sendpacket((pcap_t *)pcapDev, (unsigned char *)packet, ea.GetPacketSize(packet));
	error = "";
	return true;
}

bool DrcomForJY::WaitingRequestPasswork(char id[1], char challengeMD5[16])
{
	overedTime = overTime;				//重置超时时间
	EAPOL ea;
	char packet[EAPOL::PACKET_MAX_SIZE] ={0};
	while (true)
	{
		struct pcap_pkthdr *header;
		const unsigned char *pkt_data;

		int res = pcap_next_ex((pcap_t *)pcapDev, &header, &pkt_data);
		if (res == -1)		//出错
		{
			error = "pcap接收包出错";
			return false;
		}
		else if (res == 0)	//超时
		{
			if (overedTime <= 0)
			{
				error = "服务器无响应";
				return false;
			}
			overedTime -= listenTime;
			continue;
		}

		//收到一个包
		memcpy_s(&packet, sizeof(packet), pkt_data, sizeof(packet) < header->len ? sizeof(packet) : header->len);

		char dstMac[6];
		ea.GetDst(packet, dstMac);

		if (memcmp(dstMac, clientMac, 6) == 0)		//判断是否是发到本机的数据包
		{
			if (ea.GetEap(packet))					//是否为Eap协议的包
			{
				if (!memcmp(ea.GetEap(packet)->code, ea.Eap_Code_Request, sizeof EAPOL::Eap::code) &&
					!memcmp(ea.GetEap(packet)->type, ea.Eap_Type_Md5Challenge, sizeof EAPOL::Eap::type))			//是否为Request的请求包，是否为Md5Challenge要求Md5挑战密匙认证的包
				{
					memcpy(id, ea.GetEap(packet)->id, sizeof EAPOL::Eap::id);
					memcpy(challengeMD5, ea.GetMd5Challenge(packet)->value, sizeof EAPOL::Md5Challenge::value);
					error = "";
					return true;
				}
				else if (!memcmp(ea.GetEap(packet)->code, ea.Eap_Code_Failure, sizeof EAPOL::Eap::code))
				{
					error = "服务器拒绝认证";
					return false;
				}
				//来到这里，一般是收错包了，继续接收包
			}
		}
	}
	error = "未知错误";
	return false;
}

bool DrcomForJY::ResponsePasswork(char id[1], const char * userName, const char * pwd, const char challengeMD5[16])
{
	if (!pcapDev)
	{
		error = "未选择网卡";
		return false;
	}

	auto EncryptMD5 = [](const char *pwd, const char id[1], const char challengeMD5[16], char output[16]) -> void
	{
		unsigned char TmpBuf[1 + 64 + 16];
		MD5_CTX md5T;
		memcpy(TmpBuf, id, 1);
		memcpy(TmpBuf + 0x01, pwd, strlen(pwd));
		memcpy(TmpBuf + 0x01 + strlen(pwd), challengeMD5, 16);
		MD5Init(&md5T);
		MD5Update(&md5T, TmpBuf, 17 + strlen(pwd));
		MD5Final((UCHAR *)output, &md5T);
	};

	//不知什么用，跟在userName后面
	//注意，跟ResponseUserName的unknow不一样，在第4个字节不同
	//unknow的最后4个字节为本机IP地址
	char unknow[] ={
		0x00, 0x44, 0x61, 0x22, 0x00, 0xff, 0xff, 0xff,
		0xff
	};

	//设置IP
	memcpy(unknow + sizeof(unknow) - 4, clientIp, 4);

	//生成挑战密码
	char *userNameAfter = new char[strlen(userName) + sizeof unknow];
	char passwordMd5[16];
	EncryptMD5(pwd, id, challengeMD5, passwordMd5);

	//生成用户id
	strcpy(userNameAfter, userName);
	memcpy(userNameAfter + strlen(userName), unknow, sizeof unknow);

	//制作包
	EAPOL ea;
	char packet[EAPOL::PACKET_MAX_SIZE] ={0};
	ea.SetDst(packet, NearestMac);
	ea.SetSrc(packet, clientMac);
	ea.SetEapol(packet, ea.Eapol_Type_Eap);
	ea.SetEap(packet, ea.Eap_Code_Response, id, ea.Eap_Type_Identity);
	ea.SetMd5Challenge(packet, passwordMd5, userNameAfter, strlen(userName) + sizeof unknow);
	delete userNameAfter;
	pcap_sendpacket((pcap_t *)pcapDev, (unsigned char *)packet, ea.GetPacketSize(packet));
	error = "";
	return true;
}

bool DrcomForJY::WaitingSuccess()
{
	overedTime = overTime;		//重置超时时间
	EAPOL ea;
	char packet[EAPOL::PACKET_MAX_SIZE] ={0};
	while (true)
	{
		struct pcap_pkthdr *header;
		const unsigned char *pkt_data;

		int res = pcap_next_ex((pcap_t *)pcapDev, &header, &pkt_data);
		if (res == -1)		//出错
		{
			error = "pcap接收包出错";
			return false;
		}
		else if (res == 0)	//超时
		{
			if (overedTime <= 0)
			{
				error = "服务器无响应，可能密码错误";
				return false;
			}
			overedTime -= listenTime;
			continue;
		}

		//收到一个包
		memcpy_s(&packet, sizeof(packet), pkt_data, sizeof(packet) < header->len ? sizeof(packet) : header->len);

		char dstMac[6];
		ea.GetDst(packet, dstMac);

		if (memcmp(dstMac, clientMac, 6) == 0)		//判断是否是发到本机的数据包
		{
			if (ea.GetEap(packet))					//是否为Eap协议的包
			{
				if (!memcmp(ea.GetEap(packet)->code, ea.Eap_Code_Success, sizeof EAPOL::Eap::code))			//是否成功
				{
					error = "";
					return true;
				}
				else if (!memcmp(ea.GetEap(packet)->code, ea.Eap_Code_Failure, sizeof EAPOL::Eap::code))	//密码错误
				{
					error = "服务器拒绝认证";
					return false;
				}
				//来到这里，一般是收错包了，继续接收包
			}
		}
	}
	error = "未知错误";
	return false;
}
