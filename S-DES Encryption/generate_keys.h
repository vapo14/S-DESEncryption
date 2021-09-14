//
//  generate_keys.h
//  S-DES Encryption
//
//  Created by Victor Padron on 02/09/21.
//

#ifndef generate_keys_h
#define generate_keys_h

#include <string>

using namespace std;

// helper functions
string P10(string key);
string P8(string key);
string left_shift(string key, int offset);
string merge(string key1, string key2);


// struct definition for splitting keys
struct splitKeys {
    string leftHalf;
    string rightHalf;
};

struct Keys {
    string key1;
    string key2;
};

splitKeys split(string key);


Keys generate_keys(string selectedKey, bool verbose = false);

#endif /* generate_keys_h */
