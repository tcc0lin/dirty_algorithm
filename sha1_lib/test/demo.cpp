#include <iostream>
#include "sha1.h"
using namespace std;

int main(int argc, char *argv[]) {
    SHA1 sha1;
    std::string myHash  = sha1("Hello World");
    if (argc != 2) {
        cout << "usage: ./demo string" << endl;
    } else {
        cout << "sha1 of '" << argv[1] << "': " << myHash << endl;
    }
    return 0;
}
