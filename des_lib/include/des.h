#ifndef DES_H_
#define DES_H_
#include <string>
using namespace std;

class DES_Encryption{
public:
	void encrypt(string plain_txt, string key);
};
#endif /* DES_H_ */
