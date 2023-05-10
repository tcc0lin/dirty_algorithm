#include <iostream>
#include "base64.h"
using namespace std;

int main(int argc, char *argv[]) {
    if (argc != 3) {
        cout << "usage: ./demo encode/decode string" << endl;
    } else {
        if (!strcmp(argv[1],"encode")){
            cout << "base64_encode of '" << argv[2] << "': " << base64_encode(argv[2]) << endl;
        }else{
            cout << "base64_decode of '" << argv[2] << "': " << base64_decode(argv[2]) << endl;
        }
    }
    return 0;
}
