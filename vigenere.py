#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Basic implementation from https://gist.github.com/dssstr/aedbb5e9f2185f366c6d6b50fad3e4a4

import os
import sys
import argparse

dictionary_path = os.path.join(os.path.dirname(__file__), 'JdP_vigenere_alumnos_20200326', 'JdP_001_dictionary')
hash_path = os.path.join(os.path.dirname(__file__), 'JdP_vigenere_alumnos_20200326', 'JdP_001_hash')
input_path = os.path.join(os.path.dirname(__file__), 'JdP_vigenere_alumnos_20200326', 'JdP_001_input')

dictionary_str = next(open(dictionary_path)).rstrip()
dictionary = [c for c in dictionary_str]

def encrypt(plaintext, key, dictionary):
    dictionary_len = len(dictionary)
    key_length = len(key)
    key_as_int = [dictionary.index(c) for c in key]
    plaintext_int = [dictionary.index(c) for c in plaintext]
    ciphertext = ''
    for i in range(len(plaintext_int)):
        value = (plaintext_int[i] + key_as_int[i % key_length]) % dictionary_len
        ciphertext += dictionary[value]
    return ciphertext

def decrypt(ciphertext, key, dictionary):
    dictionary_len = len(dictionary)
    key_length = len(key)
    key_as_int = [dictionary.index(c) for c in key]
    ciphertext_int = [dictionary.index(c) for c in ciphertext]
    plaintext = ''
    for i in range(len(ciphertext_int)):
        value = (ciphertext_int[i] - key_as_int[i % key_length]) % dictionary_len
        plaintext += dictionary[value]
    return plaintext


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Algorithm for cypher and decypher texts.', 
        add_help=True)
    parser.add_argument('-i', metavar='INPUT', nargs='?', type=argparse.FileType(), 
        help='Path for the input file.')
    parser.add_argument('-d', metavar='DICTIONARY', nargs='?', type=argparse.FileType(), 
        help='Path for the dictionary file.')
    parser.add_argument('--hash', metavar='HASH', nargs='?', type=argparse.FileType(), 
        help='Path for the hash file.')
    args = parser.parse_args()

    if (not args.i):
        print('Path for the input file needed.')
        sys.exit()
    if (not args.d):
        print('Path for the dictionary file needed.')
        sys.exit()
    if (not args.hash):
        print('Path for the hash file needed.')
        sys.exit()

    proccessed_text = args.i.read()
    dictionary_text = args.d.read()
    hash_text = args.hash.read()