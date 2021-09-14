//
//  main.cpp
//  S-DES Encryption
//
//  Created by Victor Padron on 02/09/21.
//

#include <iostream>
#include <string>
#include <vector>
#include "generate_keys.h"
#include "encrypt_decrypt.h"
#include "parser.h"
#include "brute_force.h"

using namespace std;

bool verbose;
string mode = "NONE";
string filePath;
string plaintext = "";
string key = "";
string ciphertext = "";

void setFlags();

vector<string> keyCollection = {"0000000000"};

int main(int argc, char **argv)
{
    if(argc <= 1){
        cout << "Usage: \nSDES <mode> <full_filepath> <verbose> for brute force\nSDES <mode> <plaintext/ciphertext> <key> <verbose> for normal encryption / decryption.\n\nSDES e 01100110 1100101010\n\nSDES b /some/filepath/file.txt" << endl;
    }else{
        if(*argv[1] == 'b'){
            mode = "BRUTE_FORCE";
            filePath = argv[2];
            if(argc > 3)
                verbose = true;
        }else if(*argv[1] == 'e'){
            mode = "ENCRYPT";
            plaintext = argv[2];
            key = argv[3];
            if(argc > 4)
                verbose = true;
        }else if(*argv[1] == 'd'){
            mode = "DECRYPT";
            plaintext = argv[2];
            key = argv[3];
            if(argc > 4)
                verbose = true;
        }else{
            cout << "Usage: \nSDES <mode> <path> <verbose> for brute force\nSDES <mode> <plaintext> <key> for normal encryption.\n\nSDES e 01100110 1100101010\n\nSDES b ./file.txt" << endl;
            return 2;
        }
    }
    
    if(mode == "ENCRYPT"){
        cout << "\nEncrypted string: " + encrypt_decrypt(generate_keys(key, verbose), plaintext, mode, verbose) << endl;
    }else if(mode == "DECRYPT"){
        cout << "\nDecrypted string: " + encrypt_decrypt(generate_keys(key, verbose), plaintext, mode, verbose) << endl;
    }
    else if(mode == "BRUTE_FORCE"){
        
        //get list of plaintext and key inputs
        vector<string> list;
        try {
            list = get_inputs(filePath);
            // for each pair of plaintext and ciphertext
            for(int i = 0; i < list.size(); i++){
                // perform brute force
                plaintext = split_data(list[i], ',').plaintext;
                ciphertext = split_data(list[i], ',').ciphertext;
                key = keyCollection[i];
                // get first key that matches pair
                // if no key found for a given pair, return. There is no common key.
                string matchedKey = brute_force(plaintext, ciphertext, key);
                if(matchedKey == ""){
                    cout << "Key not found in line #"+ to_string(i) << endl;
                    return 1;
                }
                // Add matched key to key collection
                keyCollection.push_back(matchedKey);
            }
            bool passed = false;
            // get the most repeated key in collection
            key = most_occurred(keyCollection);
            // use the key and compare each pair
            // if it matches for all pairs, it is the common key
            Keys keys = generate_keys(key);
            for(int i = 0; i < list.size(); i++){
                plaintext = split_data(list[i], ',').plaintext;
                ciphertext = split_data(list[i], ',').ciphertext;
                if(encrypt_decrypt(keys, plaintext, "ENCRYPT") == ciphertext){
                    passed = true;
                }else{
                    break;
                }
            }
            if(passed){
                cout << "Common Key: " + key << endl;
            }else{
                cout << "No common key found." << endl;
            }
        } catch (const exception &exc) {
            cerr << exc.what();
        }
    }
    return 0;
}
