#include <fstream>
#include <string.h>
#include <stdlib.h>
#include "SHA.hpp"

using namespace std;

int main() 
{
    // import the file and process it to be used as a char *
    ifstream file("Mark.txt");
    string str((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    const char* gospel = str.c_str();

    // testing output
        // string test = "abc";
        // gospel = test.c_str();

        // SHA-256 for abc
        // ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad

    SHA * gospelHash = new SHA(gospel);
};