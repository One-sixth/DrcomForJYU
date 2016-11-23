#ifndef EAPOL_H
#define EAPOL_H

//以太网包里面的整数是大序的
//x86计算机的整数是小序的
//所以使用时需要翻转字节序
#pragma pack(1)
class EAPOL
{
public:
	static const unsigned short PACKET_MAX_SIZE = 1500;
	struct EtherType
	{
		char dst[6];
		char src[6];
		char type[2];
	};
	const char EtherType_Type_Eapol[sizeof EtherType::type] ={'\x88', '\x8e'};
	struct Eapol : public EtherType
	{
		char version[1];
		char type[1];
		char length[2];			//后面Eap包的大小
	};
	const char Eapol_Version[sizeof Eapol::version] ={'\x01'};
	const char Eapol_Type_Start[sizeof Eapol::type] ={'\x01'};
	const char Eapol_Type_Eap[sizeof Eapol::type] ={'\x00'};
	const char Eapol_Type_Logoff[sizeof Eapol::type] ={'\x02'};
	struct Eap : public Eapol
	{
		char code[1];
		char id[1];
		char length[2];			//这个Eap包的大小
		char type[1];
	};
	const char Eap_Code_Request[sizeof Eap::code] ={'\x01'};
	const char Eap_Code_Response[sizeof Eap::code] ={'\x02'};
	const char Eap_Code_Success[sizeof Eap::code] ={'\x03'};
	const char Eap_Code_Failure[sizeof Eap::code] ={'\x04'};
	const char Eap_Type_Md5Challenge[sizeof Eap::type] ={'\x04'};
	const char Eap_Type_Identity[sizeof Eap::type] ={'\x01'};
	struct Md5Challenge : public Eap
	{
		char valueSize[1];
		char value[16];
		char extraData[1];		//仅用做占位，大小未知
	};
	const char Md5Challenge_valueSize[sizeof Md5Challenge::valueSize] ={char(sizeof Md5Challenge::value)};
public:

	void GetSrc(void *packet, char data[6]);
	void GetDst(void *packet, char data[6]);
	Eapol* GetEapol(void *packet);
	Eap* GetEap(void *packet);
	Md5Challenge* GetMd5Challenge(void *packet);
	char* GetMd5ChallengeExtraData(void *packet, unsigned short *size);
	char* GetEapIdentity(void *packet, unsigned short *size);

	unsigned short GetPacketSize(void *packet);

	void SetSrc(void *packet, const char data[6]);
	void SetDst(void *packet, const char data[6]);
	Eapol* SetEapol(void *packet, const char type[1], unsigned short length = 0);
	Eap* SetEap(void * packet, const char code[1], const char id[1], const char type[1], unsigned short length = sizeof(Eap) - sizeof(Eapol));
	Md5Challenge* SetMd5Challenge(void *packet, const char value[16], const char *extraData, unsigned short extraDataSize);
	Eap* SetEapExtraData(void *packet, const char type[1], const char *extraData, unsigned short extraDataSize);

	//翻转字节顺序
	unsigned short FlipShort(unsigned short a);
};

#endif
