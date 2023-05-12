#include <iostream>
#include "sha1.h"
using namespace std;

int main() {
    unsigned char m[56] = "123";
	unsigned int c[5] = { 0 };
	SHA1(m,c);
	for (int j = 0; j <= 4; j++) printf("%08X", c[j]);
    return 0;
}
