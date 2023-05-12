#include <iostream>
#include "sha256.h"
using namespace std;

int main() {
    string s = "hello world";
	SHA256 sha;
	sha.update(s);
	uint8_t * digest = sha.digest();

	std::cout << SHA256::toString(digest) << std::endl;	
    delete[] digest;
	return 0;
}