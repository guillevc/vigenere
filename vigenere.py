#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import argparse

def main():  
    parser = argparse.ArgumentParser(description='Algorithm for cypher and decypher texts.', 
        add_help=False)
    parser.add_argument('-i', metavar='INPUT', nargs='?', type=argparse.FileType(), 
        help='Path for the input file.', required=True)
    parser.add_argument('-d', metavar='DICTIONARY', nargs='?', type=argparse.FileType(), 
        help='Path for the dictionary file.', required=True)
    parser.add_argument('--hash', metavar='HASH', nargs='?', type=argparse.FileType(), 
        help='Path for the hash file.', required=True)
    args = parser.parse_args()
    
    proccessed_text = args.i.read()
    dictionary_text = args.d.read()
    hash_text = args.hash.read()

# Source: https://gist.github.com/dssstr/aedbb5e9f2185f366c6d6b50fad3e4a4
def encrypt(plaintext, key, dictionary):
    dictionary_length = len(dictionary)
    key_length = len(key)
    key_indexes = [dictionary.index(c) for c in key]
    plaintext_indexes = [dictionary.index(c) for c in plaintext]
    ciphertext = ''
    for i in range(len(plaintext_indexes)):
        value = (plaintext_indexes[i] + key_indexes[i % key_length]) % dictionary_length
        ciphertext += dictionary[value]
    return ciphertext

def decrypt(ciphertext, key, dictionary):
    dictionary_length = len(dictionary)
    key_length = len(key)
    key_indexes = [dictionary.index(c) for c in key]
    ciphertext_indexes = [dictionary.index(c) for c in ciphertext]
    plaintext = ''
    for i in range(len(ciphertext_indexes)):
        value = (ciphertext_indexes[i] - key_indexes[i % key_length]) % dictionary_length
        plaintext += dictionary[value]
    return plaintext


if __name__ == "__main__":
    main()