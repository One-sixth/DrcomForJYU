#include "EAPOL.h"
#include <string.h>
#include <stdlib.h>
#include <stddef.h>

void EAPOL::GetSrc(void *packet, char data[6])
{
	memcpy(data, ((EtherType*)packet)->src, 6);
}

void EAPOL::GetDst(void *packet, char data[6])
{
	memcpy(data, ((EtherType*)packet)->dst, 6);
}

EAPOL::Eapol* EAPOL::GetEapol(void *packet)
{
	if (memcmp(((EtherType*)packet)->type, EtherType_Type_Eapol, sizeof(EtherType::type)))
		return nullptr;
	return (Eapol *)packet;
}

EAPOL::Eap* EAPOL::GetEap(void *packet)
{
	Eapol *p = GetEapol(packet);
	if (!p)
		return nullptr;
	if (memcmp(p->type, Eapol_Type_Eap, sizeof(Eapol::type)))
		return nullptr;
	return (Eap *)packet;
}

EAPOL::Md5Challenge* EAPOL::GetMd5Challenge(void *packet)
{
	Eap *p = GetEap(packet);
	if (!p)
		return nullptr;
	if (memcmp(p->type, Eap_Type_Md5Challenge, sizeof(Eap::type)))
		return nullptr;
	return (Md5Challenge *)packet;
}

char* EAPOL::GetMd5ChallengeExtraData(void *packet, unsigned short *size)
{
	Md5Challenge *p3 = GetMd5Challenge(packet);
	if (!p3)
		return nullptr;
	Eap *p2 = GetEap(packet);
	auto tmp = FlipShort(*(unsigned short *)p2->length);
	*size = tmp - (p3->extraData - p2->code);
	return p3->extraData;
}

char* EAPOL::GetEapIdentity(void *packet, unsigned short *size)
{
	Eap *p2 = GetEap(packet);
	if (!p2)
		return nullptr;
	auto tmp = FlipShort(*(unsigned short *)p2->length);
	*size = GetPacketSize(packet) - sizeof(Eap);
	return p2->type + sizeof(Eap::type);
	return (char *)packet + sizeof(Eap);
}

unsigned short EAPOL::GetPacketSize(void *packet)
{
	unsigned short size = sizeof(EtherType);		//至少有EtherType大

	//不识别其他帧类型
	Eapol *p1 = GetEapol(packet);
	if (!p1)
		return size;
	size = sizeof(Eapol);
	Eap *p2 = GetEap(p1);
	if (!p2)
		return size;
	size += FlipShort(*(unsigned short *)p2->length);

	return size;
}

void EAPOL::SetSrc(void *packet, const char data[6])
{
	memcpy(((EtherType *)packet)->src, data, 6);
}

void EAPOL::SetDst(void *packet, const char data[6])
{
	memcpy(((EtherType *)packet)->dst, data, 6);
}

EAPOL::Eapol * EAPOL::SetEapol(void *packet, const char type[1], unsigned short length)
{
	EtherType *p1 = (EtherType *)packet;
	memcpy(p1->type, EtherType_Type_Eapol, sizeof(EtherType::type));
	Eapol *p2 = (Eapol *)p1;
	memcpy(p2->version, Eapol_Version, sizeof(Eapol::version));
	memcpy(p2->type, type, sizeof(Eapol::type));
	unsigned short tmp = FlipShort(length);
	memcpy(p2->length, &tmp, sizeof(Eapol::length));
	return p2;
}

EAPOL::Eap* EAPOL::SetEap(void *packet, const char code[1], const char id[1], const char type[1], unsigned short length)
{
	Eap *p2 = (Eap *)SetEapol(packet, Eapol_Type_Eap, length);
	memcpy(p2->code, code, sizeof(Eap::code));
	memcpy(p2->id, id, sizeof(Eap::id));
	unsigned short tmp = FlipShort(length);
	memcpy(p2->length, &tmp, sizeof(Eapol::length));
	memcpy(p2->type, type, sizeof(Eap::type));
	return p2;
}

EAPOL::Md5Challenge* EAPOL::SetMd5Challenge(void *packet, const char value[16], const char *extraData, unsigned short extraDataSize)
{
	Eap *p2 = GetEap(packet);
	if (!p2)
		return nullptr;
	memcpy(p2->type, Eap_Type_Md5Challenge, sizeof Eap::type);
	Md5Challenge *p3 = (Md5Challenge *)p2;
	memcpy(p3->value, value, 16);
	memcpy(p3->valueSize, Md5Challenge_valueSize, sizeof Md5Challenge::valueSize);
	unsigned int extraDataOffset = sizeof(Md5Challenge) - sizeof(Md5Challenge::extraData);
	memcpy((char *)packet + extraDataOffset, extraData, extraDataSize);

	//计算单纯Eap包的大小
	unsigned short tmp = extraDataOffset + extraDataSize - sizeof(Eapol);
	SetEapol(packet, Eapol_Type_Eap, tmp);
	SetEap(packet, p2->code, p2->id, p2->type, tmp);
	return p3;
}

EAPOL::Eap* EAPOL::SetEapExtraData(void *packet, const char type[1], const char *extraData, unsigned short extraDataSize)
{
	Eap *p2 = GetEap(packet);
	if (!p2)
		return nullptr;
	memcpy(p2->type, type, sizeof Eap::type);
	unsigned int extraDataOffset = sizeof(Eap);
	memcpy((char *)packet + extraDataOffset, extraData, extraDataSize);

	//计算单纯Eap包的大小
	unsigned short tmp = sizeof(Eap) + extraDataSize;
	SetEapol(packet, Eapol_Type_Eap, tmp);
	SetEap(packet, p2->code, p2->id, p2->type, tmp);
	return p2;
}

unsigned short EAPOL::FlipShort(unsigned short a)
{
	char b;
	b = *(char *)&a;
	*(char *)&a = *((char *)&a + 1);
	*((char *)&a + 1) = b;
	return a;
}
