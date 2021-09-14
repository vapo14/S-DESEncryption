//
//  Encrypt.cpp
//  S-DES Encryption
//
//  Created by Victor Padron on 02/09/21.
//

#include "generate_keys.h"
#include "encrypt_decrypt.h"
#include <iostream>
#include <string>
#include <map>
#include <bitset>


string encrypt_decrypt(Keys keys, string plaintext, string mode, bool verbose) {
    string ciphertext = "";
    if(mode == "ENCRYPT"){
        if (verbose) {
            string IP8Text = IP8(plaintext);
            cout << "\n===== Encrypting plaintext: " + plaintext + " with keys: " + "1. " + keys.key1 + " 2. " + keys.key2 + " ======\n" << endl;
            cout << "IP8 Text: " + IP8Text << endl;
            splitKeys halves = split(IP8Text);
            string expandedRight = ExpandPermutate(halves.rightHalf);
            cout << "Expanded right " + halves.rightHalf + " output: " + expandedRight << endl;
            string xorOutput = XOR(expandedRight, keys.key1);
            cout << "XOR Output: " + xorOutput << endl;
            splitKeys splitXOROutput = split(xorOutput);
            S0Box(splitXOROutput.leftHalf);
            S1Box(splitXOROutput.rightHalf);
            string mergeForP4 = merge(S0Box(splitXOROutput.leftHalf), S1Box(splitXOROutput.rightHalf));
            string afterP4 = P4(mergeForP4);
            cout << "Applying P4: " + afterP4 << endl;
            string afterXORP4 = XOR(halves.leftHalf, afterP4);
            cout << "XOR after P4: " + afterXORP4 << endl;
            string secondPerm = ExpandPermutate(afterXORP4);
            secondPerm = XOR(secondPerm, keys.key2);
            cout << "XOR with second key: " + secondPerm << endl;
            splitKeys finalSplit = split(secondPerm);
            secondPerm = merge(S0Box(finalSplit.leftHalf), S1Box(finalSplit.rightHalf));
            cout << "Merge after SBoxes: " + secondPerm << endl;
            secondPerm = P4(secondPerm);
            cout << "Applying P4 permutation: " + secondPerm << endl;
            secondPerm = XOR(secondPerm, halves.rightHalf);
            cout << "Applying final 4 bit XOR: " + secondPerm << endl;
            secondPerm = merge(secondPerm, afterXORP4);
            cout << "Final merge: " + secondPerm << endl;
            cout << "Encrypted text: " + FinalPermutation(secondPerm) << endl;
            ciphertext = FinalPermutation(secondPerm);
        }
        else {
            string IP8Text = IP8(plaintext);
            splitKeys halves = split(IP8Text);
            string expandedRight = ExpandPermutate(halves.rightHalf);
            string xorOutput = XOR(expandedRight, keys.key1);
            splitKeys splitXOROutput = split(xorOutput);
            string mergeForP4 = merge(S0Box(splitXOROutput.leftHalf), S1Box(splitXOROutput.rightHalf));
            string afterP4 = P4(mergeForP4);
            string afterXORP4 = XOR(halves.leftHalf, afterP4);
            string secondPerm = ExpandPermutate(afterXORP4);
            secondPerm = XOR(secondPerm, keys.key2);
            splitKeys finalSplit = split(secondPerm);
            secondPerm = merge(S0Box(finalSplit.leftHalf), S1Box(finalSplit.rightHalf));
            secondPerm = P4(secondPerm);
            secondPerm = XOR(secondPerm, halves.rightHalf);
            secondPerm = merge(secondPerm, afterXORP4);
            ciphertext = FinalPermutation(secondPerm);
        }
    }else if(mode == "DECRYPT"){
        if (verbose) {
            string IP8Text = IP8(plaintext);
            cout << "\n===== Decrypting plaintext: " + plaintext + " with keys: " + "1. " + keys.key1 + " 2. " + keys.key2 + " ======\n" << endl;
            cout << "IP8 Text: " + IP8Text << endl;
            splitKeys halves = split(IP8Text);
            string expandedRight = ExpandPermutate(halves.rightHalf);
            cout << "Expanded right " + halves.rightHalf + " output: " + expandedRight << endl;
            string xorOutput = XOR(expandedRight, keys.key2);
            cout << "XOR Output: " + xorOutput << endl;
            splitKeys splitXOROutput = split(xorOutput);
            S0Box(splitXOROutput.leftHalf);
            S1Box(splitXOROutput.rightHalf);
            string mergeForP4 = merge(S0Box(splitXOROutput.leftHalf), S1Box(splitXOROutput.rightHalf));
            string afterP4 = P4(mergeForP4);
            cout << "Applying P4: " + afterP4 << endl;
            string afterXORP4 = XOR(halves.leftHalf, afterP4);
            cout << "XOR after P4: " + afterXORP4 << endl;
            string secondPerm = ExpandPermutate(afterXORP4);
            secondPerm = XOR(secondPerm, keys.key1);
            cout << "XOR with second key: " + secondPerm << endl;
            splitKeys finalSplit = split(secondPerm);
            secondPerm = merge(S0Box(finalSplit.leftHalf), S1Box(finalSplit.rightHalf));
            cout << "Merge after SBoxes: " + secondPerm << endl;
            secondPerm = P4(secondPerm);
            cout << "Applying P4 permutation: " + secondPerm << endl;
            secondPerm = XOR(secondPerm, halves.rightHalf);
            cout << "Applying final 4 bit XOR: " + secondPerm << endl;
            secondPerm = merge(secondPerm, afterXORP4);
            cout << "Final merge: " + secondPerm << endl;
            cout << "Encrypted text: " + FinalPermutation(secondPerm) << endl;
            ciphertext = FinalPermutation(secondPerm);
        }
        else {
            string IP8Text = IP8(plaintext);
            splitKeys halves = split(IP8Text);
            string expandedRight = ExpandPermutate(halves.rightHalf);
            string xorOutput = XOR(expandedRight, keys.key2);
            splitKeys splitXOROutput = split(xorOutput);
            string mergeForP4 = merge(S0Box(splitXOROutput.leftHalf), S1Box(splitXOROutput.rightHalf));
            string afterP4 = P4(mergeForP4);
            string afterXORP4 = XOR(halves.leftHalf, afterP4);
            string secondPerm = ExpandPermutate(afterXORP4);
            secondPerm = XOR(secondPerm, keys.key1);
            splitKeys finalSplit = split(secondPerm);
            secondPerm = merge(S0Box(finalSplit.leftHalf), S1Box(finalSplit.rightHalf));
            secondPerm = P4(secondPerm);
            secondPerm = XOR(secondPerm, halves.rightHalf);
            secondPerm = merge(secondPerm, afterXORP4);
            ciphertext = FinalPermutation(secondPerm);
        }
    }
    return ciphertext;
}

// initial permutation of 8 bits
string IP8(string plaintext) {
    string temp;
    int permutation[8] = { 2, 6, 3, 1, 4, 8, 5, 7 };

    for (size_t i = 0; i < plaintext.length(); i++) {
        temp.push_back(plaintext[permutation[i] - 1]);
    }
    return temp;
}

// expand and permutate helper function
string ExpandPermutate(string key) {
    string temp;
    int permutation[8] = { 4, 1, 2, 3, 2, 3, 4, 1 };
    for (int i = 0; i < 8; i++) {
        temp.push_back(key[permutation[i] - 1]);
    }

    return temp;
}

// XOR for two strings helper function
string XOR(string key1, string key2) {
    string temp;
    char tempChar;
    for (size_t i = 0; i < key1.length(); i++) {
        tempChar = '0' + abs((int)key1[i] - (int)key2[i]);
        temp.push_back(tempChar);
    }
    return temp;
}

// returns the S0Box of a given two bit key
string S0Box(string key) {
    string temp;
    string row;
    string column;
    map<string, int> bin;
    bin["00"] = 0;
    bin["01"] = 1;
    bin["10"] = 2;
    bin["11"] = 3;
    int SBox[4][4] =
    {
        {1, 0, 3, 2},
        {3, 2, 1, 0},
        {0, 2, 1, 3},
        {3, 1, 3, 2}
    };
    row.push_back(key[0]);
    row.push_back(key[key.length() - 1]);
    column.push_back(key[1]);
    column.push_back(key[key.length() - 2]);
    //cout << "\n\nRow: " + row + "\nColumn: " + column << endl;
    //cout << "S0Box Values: " + bitset<2>(SBox[bin[row]][bin[column]]).to_string() << endl;
    temp = bitset<2>(SBox[bin[row]][bin[column]]).to_string();
    return temp;
}

// returns the S1Box of a given two bit key
string S1Box(string key) {
    string temp;
    string row;
    string column;
    map<string, int> bin;
    bin["00"] = 0;
    bin["01"] = 1;
    bin["10"] = 2;
    bin["11"] = 3;
    int SBox[4][4] =
    {
        {0, 1, 2, 3},
        {2, 0, 1, 3},
        {3, 0, 1, 0},
        {2, 1, 0, 3}
    };
    row.push_back(key[0]);
    row.push_back(key[key.length() - 1]);
    column.push_back(key[1]);
    column.push_back(key[key.length() - 2]);
    //cout << "\n\nRow: " + row + "\nColumn: " + column << endl;
    //cout << "S1Box Values: " + bitset<2>(SBox[bin[row]][bin[column]]).to_string() << endl;
    temp = bitset<2>(SBox[bin[row]][bin[column]]).to_string();
    return temp;
}

// P4 permutation helper function
string P4(string key) {
    string temp;
    int permutation[4] = { 2, 4, 3, 1 };

    for (size_t i = 0; i < key.length(); i++) {
        temp.push_back(key[permutation[i] - 1]);
    }
    return temp;
}

// final permutation helper function
string FinalPermutation(string key) {
    string temp;
    int permutation[10] = { 4, 1, 3, 5, 7, 2, 8, 6 };
    for (size_t i = 0; i < key.length(); i++) {
        temp.push_back(key[permutation[i] - 1]);
    }
    return temp;
}
