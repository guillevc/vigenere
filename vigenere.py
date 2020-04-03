#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

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
