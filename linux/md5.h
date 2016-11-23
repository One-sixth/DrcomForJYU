#ifndef MD5_H
#define MD5_H

typedef unsigned char*          PUCHAR;
typedef unsigned short int      UINT2;
typedef unsigned int            UINT4;
typedef unsigned char           UCHAR;

struct MD5_CTX
{
	UINT4 state[4];
	UINT4 count[2];
	UCHAR buffer[64];
};

void MD5Init(MD5_CTX* Md5_ctx);
void MD5Update(MD5_CTX* Md5_ctx, PUCHAR Input, UINT4 Legth);
void MD5Final(UCHAR Digest[16], MD5_CTX* Md5_ctx);

#endif
