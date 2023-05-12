#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#pragma warning(disable:4996)

//初始化链接变量
unsigned int A = 0x67452301, B = 0xEFCDAB89, C = 0x98BADCFE, D = 0x10325476, E = 0xC3D2E1F0;        //第一次迭代的链接变量

unsigned int K[4] = { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };                              //循环中用到的常量
unsigned int A0 = 0x67452301, B0 = 0xEFCDAB89, C0 = 0x98BADCFE, D0 = 0x10325476, E0 = 0xC3D2E1F0;

// 字节转换，将四个字节转换为一个整型
int CharToWord(unsigned char *context, int i)
{
	return (((int)context[i] & 0x000000ff) << 24) | (((int)context[i + 1] & 0x000000ff) << 16) | (((int)context[i + 2] & 0x000000ff) << 8) | ((int)context[i + 3] & 0x000000ff);
}

// 填充补位获得原始明文
void SHA1_fill(unsigned char *plaintext, unsigned int *group, int length)
{	
	int temp = length / 32, len = length;
	while (len > 0)
	{
		if (len = len / 32)
		{
			for (int j = 0; j < temp; j++)
			{
				group[j] = CharToWord(plaintext, 4 * j);
			}
		}
		else
		{
			plaintext[length / 8] = 0x80;
			group[temp] = CharToWord(plaintext, temp * 4);
			break;
		}
	}
	group[15] = length;
}
// f函数
unsigned int f(int B, int C, int D, int t)
{
	return (t >= 0 && t <= 19) ? ((B&C) | (~B&D)) : ((t >= 20 && t <= 39) ? (B ^ C ^ D) : ((t >= 40 && t <= 59) ? ((B&C) | (B&D) | (C&D)) : ((t >= 60 && t <= 79) ? B ^ C ^ D : 0)));
}
//获得Kr
unsigned int GetK(int r)
{
	/*
	if (r >= 0&& r <= 19)
	{
		return K[0];
	}else if (r >= 20 && r <= 39)
	{
		return K[1];
	}else if (r >= 40 && r <= 59)
	{
		return K[2];
	}else if (r >= 60 && r <= 79)
	{
		return K[3];
	}
	*/
	return (r >= 0 && r <= 19) ? K[0] : ((r >= 20 && r <= 39) ? K[1] : ((r >= 40 && r <= 59) ? K[2] : ((r >= 60 && r <= 79) ? K[3] : 0)));
}

//获得 Wt
void GetW(unsigned int w[])
{
	/*
	for (int i = 16; i < 80; i++)
		w[i] = ((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]) << 1) | ((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]) >> 31);
	*/
	for (int i = 16; i < 80; w[i++] = ((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]) << 1) | ((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]) >> 31));
}
// 步函数
void StepFunction(unsigned int w[], int t)
{
	unsigned int temp = ((A << 5) | (A >> 27)) + f(B, C, D, t) + E + w[t] + GetK(t);
	E = D, D = C, C = ((B << 30) | (B >> 2)), B = A, A = temp;
}
// 获得密文
void GetCipher(unsigned int * cipher)
{
	cipher[0] = A0 + A;
	cipher[1] = B0 + B;
	cipher[2] = C0 + C;
	cipher[3] = D0 + D;
	cipher[4] = E0 + E;
}

void SHA1(unsigned char *context,unsigned int * cipher)
{
	int len = strlen((char*)context) * 8;
	unsigned int group[80] = { 0 };

	SHA1_fill(context, group, len);
	GetW(group);
	for (int t = 0; t < 80; t++)
	{
		StepFunction(group, t);
	}


	GetCipher(cipher);

}