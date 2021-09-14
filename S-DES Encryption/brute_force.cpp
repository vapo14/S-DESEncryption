//
//  brute_force.cpp
//  S-DES Encryption
//
//  Created by Victor Padron on 06/09/21.
//

#include "brute_force.h"
#include "encrypt_decrypt.h"
#include "generate_keys.h"
#include <string>
#include <iostream>
#include <bitset>
#include <vector>
#include <map>


using namespace std;


string brute_force(string plaintext, string ciphertext, string key){
    args TestArgs = {
        plaintext,
        ciphertext
    };
    TestArgs.plaintext = plaintext;
    TestArgs.ciphertext = ciphertext;
    key = get_first_match(TestArgs, key);
    return key;
}
// returns the first key that matches a plaintext and ciphertext pair
string get_first_match(args input, string key){
    string tempKey = key;
    while(encrypt_decrypt(generate_keys(tempKey), input.plaintext, "ENCRYPT") != input.ciphertext){
        // limit to largest binary key possible
        if(tempKey == "1111111111"){
            tempKey = "";
            break;
        }
        tempKey = increment_binary(tempKey);
    }
    return tempKey;
}
// increment binary represented in string
string increment_binary(string str){
    string temp = "";
    bitset<10> tempbitset(bitset<10>(str.c_str()).to_ulong() + 1);
    temp += tempbitset.to_string();
    return temp;
}
// returns the most ocurred string in a given vector
string most_occurred(const vector<string> &vec) {
  map<string,unsigned long> str_map;
  for (const auto &str : vec)
    ++str_map[str];

  typedef decltype(pair<string,unsigned long>()) pair_type;

  auto comp = [](const pair_type &pair1, const pair_type &pair2) -> bool {
    return pair1.second < pair2.second; };
  return max_element(str_map.cbegin(), str_map.cend(), comp)->first;
}
