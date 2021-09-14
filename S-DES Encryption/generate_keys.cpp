//
//  GenerateKeys.cpp
//  S-DES Encryption
//
//  Created by Victor Padron on 02/09/21.
//

#include <stdio.h>
#include <string>
#include <iostream>
#include "generate_keys.h"

using namespace std;

Keys generate_keys(string selectedKey, bool verbose) {
    Keys finalKeys;

    if (verbose) {
        cout << "P10 permutation of selected key: " << endl;
        string p10Key = P10(selectedKey);
        cout << p10Key << endl;
        cout << "Split keys: " << endl;
        cout << "Left half: ";
        splitKeys keys = split(p10Key);
        cout << keys.leftHalf << endl;
        cout << "Right half: " + keys.rightHalf << endl;
        string leftShiftLeftHalf = left_shift(keys.leftHalf, 1);
        string leftShiftRightHalf = left_shift(keys.rightHalf, 1);
        cout << "Applying left shift to left half key: " + leftShiftLeftHalf << endl;
        cout << "Applying left shift to right half key: " + leftShiftRightHalf << endl;
        string key1 = merge(leftShiftLeftHalf, leftShiftRightHalf);
        cout << "Key 1: " + key1 << endl;
        key1 = P8(key1);
        cout << "Applying P8 permutation to key 1: " + key1 << endl;
        cout << "-------------------------------------------------" << endl;
        string key2 = merge(left_shift(leftShiftLeftHalf, 2), left_shift(leftShiftRightHalf, 2));
        cout << "\nLeft shift by 2 left half: " << left_shift(leftShiftLeftHalf, 2) << endl;
        cout << "\nLeft shift by 2 right half: " << left_shift(leftShiftRightHalf, 2) << endl;
        key2 = P8(key2);
        cout << "Applying P8 permutation to key 2: " + key2 << endl;
        cout << "-------------------------------------------------" << endl;
        cout << "Key 1: " + key1 + "\nKey 2: " + key2 << endl;
        finalKeys.key1 = key1;
        finalKeys.key2 = key2;
    }
    else {
        string p10Key = P10(selectedKey);
        splitKeys keys = split(p10Key);
        string leftShiftLeftHalf = left_shift(keys.leftHalf, 1);
        string leftShiftRightHalf = left_shift(keys.rightHalf, 1);
        string key1 = merge(leftShiftLeftHalf, leftShiftRightHalf);
        key1 = P8(key1);
        string key2 = merge(left_shift(leftShiftLeftHalf, 2), left_shift(leftShiftRightHalf, 2));
        key2 = P8(key2);
        finalKeys.key1 = key1;
        finalKeys.key2 = key2;
    }
    
    return finalKeys;
}

// P10 permutation helper function
string P10(string key) {
    string p10String;
    int permutation[10] = { 3, 5, 2, 7, 4, 10, 1, 9, 8, 6 };

    for (size_t i = 0; i < key.length(); i++) {
        p10String.push_back(key[permutation[i] - 1]);
    }

    return p10String;
}


// P8 permutation helper function
string P8(string key) {
    string p8String;
    int permutation[8] = { 6, 3, 7, 4, 8, 5, 10, 9 };
    size_t arrSize = sizeof(permutation) / sizeof(permutation[0]);
    for (size_t i = 0; i < arrSize; i++) {
        p8String.push_back(key[permutation[i] - 1]);
    }
    return p8String;
}

// split string in half and return struct containing two halves
splitKeys split(string key) {
    splitKeys keys;
    for (size_t i = 0; i < key.length(); i++) {
        if (i < key.length() / 2)
            keys.leftHalf.push_back(key[i]);
        else
            keys.rightHalf.push_back(key[i]);
    }

    return keys;
}

// left shift operation on string, recieves number of bits to shift by
string left_shift(string key, int offset) {
    string temp;
    for (size_t i = offset; i < key.length() + offset; i++) {
        if (i < key.length()) {
            temp.push_back(key[i]);
        }
        else {
            temp.push_back(key[i - key.length()]);
        }
    }

    return temp;
}

// return the concatenation of two strings
string merge(string key1, string key2) {
    return key1.append(key2);
}
