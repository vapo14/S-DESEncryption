//
//  encrypt_decrypt.h
//  S-DES Encryption
//
//  Created by Victor Padron on 02/09/21.
//

#ifndef encrypt_decrypt_h
#define encrypt_decrypt_h

#include "generate_keys.h"
#include <string>

string encrypt_decrypt(Keys keys, string plaintext, string mode, bool verbose = false);
string IP8(string plaintext);
string XOR(string key1, string key2);
string ExpandPermutate(string key);
string S0Box(string key);
string S1Box(string key);
string P4(string key);
string FinalPermutation(string key);

#endif /* encrypt_decrypt */
