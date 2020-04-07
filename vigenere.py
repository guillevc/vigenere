#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import itertools
import hashlib
import time

MAX_KEY_LENGTH = 10

def main():  
    parser = argparse.ArgumentParser(description='Algorithm for cypher and decypher texts.', 
        add_help=False)
    parser.add_argument('-i', '--input', metavar='INPUT', nargs='?', type=argparse.FileType(), 
        help='Path for the input file.', required=True)
    parser.add_argument('-d', '--dictionary', metavar='DICTIONARY', nargs='?', type=argparse.FileType(), 
        help='Path for the dictionary file.', required=True)
    parser.add_argument('--hash', metavar='HASH', nargs='?', type=argparse.FileType(), 
        help='Path for the hash file.', required=True)
    args = parser.parse_args()
    
    proccessed_text = args.input.read().strip()
    dictionary_text = args.dictionary.read().strip()
    hash_text = args.hash.read().strip()
    
    # proccessed_text = 'EYKANGBAFUMMAQCZAJJUNIJNTXUTOJYCORKRAJYMAZYRIGFSASCTAXCOAIBINGKARGBACKMFRKHTEGFCOXJNABCRUYKORRCLLUHESJYEUXJSSKAUNNUEXVFICGXOEYÑEMÑYRCUFESKFMISCSTXJDEYUNIJUDSGFVAJJRIQFASKÑRAZUDERUSCGMILQUSGAUNTKNYMGÑERÑULDKKROZYCCÑJNTKNTRGKIDUNYEWOIPUNDEXYSPÑMACÑJNAYCSTÑXAIRKREYWINJCBLKNPAXULOYKACÑYNTKNMAYARABYSCUHCOBCDEYÑASKGANGÑENJMEMUNUNGKRIRYRAKHTRKAADKGATKMIAQYSHGUVASTADUBEMUNCORKRAJJYPGAADUGILQJNEYXEMGNCAXCLLGNQUKYMPKTARGHALQYGAXSAYYYGUÑMANQFEGGHDOJORASÑELGNPRURIMGNOCNJSERUNAYFLEMURASGILQJNEYXEGAUNTKNDUXUNTKFASVMOXÑGASICNCUNEMGHASKHCUGHTOGÑESZMAPÑXOSNYMOYUDQACRIJJMIQFONKNPAXULOYGESKNDERURZUSABXCLAJYMAYMECÑVIRKGOSKLUIVJSDKMESVCRAICONGNISZCDAJORASÑELUNMEYYSDKUBRÑFAJAHIONUEXVFICGXOIQFAEYÑAMUNGEYÑIOSUNDUFACUGPRGXEMGNEQACPOYBAASUDIJJELXYSPUHSAHFEDKNANÑXADNUREIJRDGXOQAYELMJBIKMNONUREVURTÑXOCGNISKCSMÑFLOSYSDKGASIURIQFASAHASICFRGNQUKXESMMANGMAEQDUEBYSESYLCUHGRKNOAJYMAYYLEOYCUZCVOKNTAGWTIBUNDUFAFGVRIIUCIUHNAICONGFDEZJDAYYSTGNCAZYGOXCASJYPRUXUCZJSRKNPIXUDOXYSMGÑERÑULDKKROZYCCÑJNYZYSTXUPIJJSEQGINÑNTRUBAAMMADKWIDUYLCUGPRUGISUXELGNEMVMESGNESVUNOQUSPGMAAJUPTGMSUYFINKUSDKKROJOCCÑJNAQUFAHMICGWIOSXEEYÑOSRUTEXCALKNYANUYDUNEMVMESGNQUKZABXCCASMESVCRAJJREYYNEYKANG'
    # dictionary_text = 'ABCDEFGHIJKLMNÑOPQRSTUVWXYZ'
    # hash_text = '5442d541845e30ef6af885af537d41d35b2fa5e21fb47a5eae98043c441362e1'
    
    start_time = time.time()
    key = guess_key(proccessed_text, dictionary_text, hash_text)
    print('Successfully guessed key {} in {} seconds'.format(key, time.time() - start_time))

def guess_key(ciphertext, dictionary, hash_text):
    key_lenghts = get_key_lengths(ciphertext)

    for key_length in key_lenghts:
        print('Attempting with key length {}...'.format(key_length))
        key = guess_key_attempt_with_key_length(ciphertext, key_length, dictionary, hash_text)
        if (key != None):
            return key
    return None

def guess_key_attempt_with_key_length(ciphertext, most_likely_key_length, dictionary, hash_text):
    for combination in itertools.product(dictionary, repeat=most_likely_key_length):
        key = ''.join(combination)
        #print('Testing with key {}'.format(key))
        decrypted_text = decrypt(ciphertext, key, dictionary)
        hashed_message = hashlib.sha256(decrypted_text.encode('utf-8')).hexdigest()
        if (hashed_message == hash_text):
            return key
    
def get_key_lengths(ciphertext):
    # Find out the sequences of 3 to 6 letters that occur multiple times
    # in the ciphertext. repeated_sequences_spacings has a value like:
    # {'EXG': [192], 'NAF': [339, 972, 633], ... }
    repeated_sequences_spacings = get_repeated_sequences_with_spacings(ciphertext, 3, 6)

    # Get factors for each sequence spacing
    sequence_factors = {}
    for seq in repeated_sequences_spacings:
        sequence_factors[seq] = []
        for spacing in repeated_sequences_spacings[seq]:
            sequence_factors[seq].extend(get_factors(spacing))

    # Sort all factors by number of occurrences, these will be the guessed key lenghts
    factors = [f for v in sequence_factors.values() for f in v if f <= MAX_KEY_LENGTH]
    factors_by_count = {}
    for factor in factors:
        if factor not in factors_by_count:
            factors_by_count[factor] = 0
        else:
            factors_by_count[factor] += 1
    key_lenghts = [k for (k, v) in sorted(factors_by_count.items(), key=lambda item: item[1], reverse=True)][0:10]

    print(key_lenghts)
    return key_lenghts

def get_repeated_sequences_with_spacings(proccessed_text, min_length, max_length):
    sequences_spacings = {} #  e.g. {sequence, [spacings]}
    for sequence_len in range(min_length, max_length + 1):
        for seq_start in range(len(proccessed_text) - sequence_len):
            # Determine what the sequence is, and store it in seq
            seq = proccessed_text[seq_start:seq_start + sequence_len]
            # Look for this sequence in the rest of the message
            for i in range(seq_start + sequence_len, len(proccessed_text) - sequence_len):
                if proccessed_text[i:i + sequence_len] == seq:
                    if seq not in sequences_spacings:
                        sequences_spacings[seq] = []
                    sequences_spacings[seq].append(i - seq_start)
    return sequences_spacings

# TODO: refactorizar
def get_factors(num):
    # Returns a list of useful factors of num. By "useful" we mean factors
    # less than MAX_KEY_LENGTH + 1. For example, get_useful_factors(144)
    # returns [2, 72, 3, 48, 4, 36, 6, 24, 8, 18, 9, 16, 12]

    if num < 2:
        return [] # numbers less than 2 have no useful factors

    factors = [] # the list of factors found

    # When finding factors, you only need to check the integers up to
    # MAX_KEY_LENGTH.
    for i in range(2, MAX_KEY_LENGTH + 1): # don't test 1
        if num % i == 0:
            factors.append(i)
            factors.append(int(num / i))
    if 1 in factors:
        factors.remove(1)
    return list(set(factors))

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

if __name__ == '__main__':
    main()
