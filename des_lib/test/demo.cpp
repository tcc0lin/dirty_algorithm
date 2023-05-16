#include <iostream>
#include "des.h"
using namespace std;

int main(int argc, char *argv[]) {
    DES_Encryption DES;

	bool is_valid;
	string plain_txt, key;
	plain_txt = "1234567812345678";
	key = "1234567812345678";
	DES.encrypt(plain_txt,key);
	return 0;
}
