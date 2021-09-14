//
//  brute_force.h
//  S-DES Encryption
//
//  Created by Victor Padron on 06/09/21.
//

#ifndef brute_force_h
#define brute_force_h

#include <stdio.h>
#include <string>
#include <vector>

using namespace std;


struct args{
    string plaintext;
    string ciphertext;
};

string brute_force(string plaintext, string ciphertext, string key);
string increment_binary(string str);
string get_first_match(args input, string key);
string most_occurred(const vector<string> &vec);


#endif /* brute_force_h */
