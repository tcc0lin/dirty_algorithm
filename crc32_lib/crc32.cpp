// CRC32.cpp : Defines the entry point for the console application.
//
#include <iostream>

using namespace std;

unsigned int uiCRC32_Table[256];


int make_crc32_table()
{
	uint32_t c;
	int i = 0;
	int bit = 0;
	
	for(i = 0; i < 256; i++)
	{
		c  = (uint32_t)i;
		
		for(bit = 0; bit < 8; bit++)
		{
			if(c&1)
			{
				c = (c >> 1)^(0xEDB88320);
			}
			else
			{
				c =  c >> 1;
			}
			
		}
		uiCRC32_Table[i] = c;
	}
}

unsigned int crc32(void *pData, size_t iLen)
{
    make_crc32_table();
	unsigned int uiCRC32 = 0xFFFFFFFF;
	unsigned char *pszData = (unsigned char*)pData;

	for (size_t i = 0; i<iLen; ++i)
		uiCRC32 = ((uiCRC32 >> 8) & 0x00FFFFFF) ^ uiCRC32_Table[(uiCRC32 ^ (unsigned int)*pszData++) & 0xFF];

	return (uiCRC32 ^ 0xFFFFFFFF);
}

int main()
{
	char* teststr = "Simple Test String!";
	unsigned int Hash = crc32(teststr, strlen(teststr));

	cout << "0x" << uppercase << hex << Hash;
}