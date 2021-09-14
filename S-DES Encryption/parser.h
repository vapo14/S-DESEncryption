//
//  Parser.h
//  S-DES Encryption
//
//  Created by Victor Padron on 03/09/21.
//

#ifndef Parser_h
#define Parser_h

#include <stdio.h>
#include <string>
#include <vector>

using namespace std;


struct Data {
    string plaintext;
    string ciphertext;
};

vector<string> get_inputs(string filePath);

Data split_data(string str, char delim);


#endif /* Parser_h */
