//
//  Parser.cpp
//  S-DES Encryption
//
//  Created by Victor Padron on 03/09/21.
//

#include "parser.h"
#include <string>
#include <vector>
#include <fstream>
#include <iostream>

using namespace std;

vector<string> get_inputs(string filePath){
    vector<string> inputs;
    
    fstream inputFile(filePath);
    string temp = "";
    while(getline(inputFile, temp)){
        inputs.push_back(temp);
    }
    inputFile.close();
    return inputs;
}


Data split_data(string str, char delim){
    bool passed = false;
    Data temp = {
        "", ""
    };
    for (int i = 0; i < str.length(); i++) {
        if(str[i] == delim){
            passed = true;
            continue;
        }
        if(passed)
            temp.ciphertext.push_back(str[i]);
        else
            temp.plaintext.push_back(str[i]);
    }
    return temp;
}
