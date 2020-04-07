#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import itertools
import hashlib

MAX_KEY_LENGTH = 10
NUM_MOST_FREQ_LETTERS = 4

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
    
    proccessed_text = args.i.read().strip().replace('\xc3\x91', 'Ñ')
    dictionary_text = args.d.read().strip().replace('\xc3\x91', 'Ñ')
    hash_text = args.hash.read().strip()

    # proccessed_text = 'EYKANGBAFUMMAQCZAJJUNIJNTXUTOJYCORKRAJYMAZYRIGFSASCTAXCOAIBINGKARGBACKMFRKHTEGFCOXJNABCRUYKORRCLLUHESJYEUXJSSKAUNNUEXVFICGXOEYÑEMÑYRCUFESKFMISCSTXJDEYUNIJUDSGFVAJJRIQFASKÑRAZUDERUSCGMILQUSGAUNTKNYMGÑERÑULDKKROZYCCÑJNTKNTRGKIDUNYEWOIPUNDEXYSPÑMACÑJNAYCSTÑXAIRKREYWINJCBLKNPAXULOYKACÑYNTKNMAYARABYSCUHCOBCDEYÑASKGANGÑENJMEMUNUNGKRIRYRAKHTRKAADKGATKMIAQYSHGUVASTADUBEMUNCORKRAJJYPGAADUGILQJNEYXEMGNCAXCLLGNQUKYMPKTARGHALQYGAXSAYYYGUÑMANQFEGGHDOJORASÑELGNPRURIMGNOCNJSERUNAYFLEMURASGILQJNEYXEGAUNTKNDUXUNTKFASVMOXÑGASICNCUNEMGHASKHCUGHTOGÑESZMAPÑXOSNYMOYUDQACRIJJMIQFONKNPAXULOYGESKNDERURZUSABXCLAJYMAYMECÑVIRKGOSKLUIVJSDKMESVCRAICONGNISZCDAJORASÑELUNMEYYSDKUBRÑFAJAHIONUEXVFICGXOIQFAEYÑAMUNGEYÑIOSUNDUFACUGPRGXEMGNEQACPOYBAASUDIJJELXYSPUHSAHFEDKNANÑXADNUREIJRDGXOQAYELMJBIKMNONUREVURTÑXOCGNISKCSMÑFLOSYSDKGASIURIQFASAHASICFRGNQUKXESMMANGMAEQDUEBYSESYLCUHGRKNOAJYMAYYLEOYCUZCVOKNTAGWTIBUNDUFAFGVRIIUCIUHNAICONGFDEZJDAYYSTGNCAZYGOXCASJYPRUXUCZJSRKNPIXUDOXYSMGÑERÑULDKKROZYCCÑJNYZYSTXUPIJJSEQGINÑNTRUBAAMMADKWIDUYLCUGPRUGISUXELGNEMVMESGNESVUNOQUSPGMAAJUPTGMSUYFINKUSDKKROJOCCÑJNAQUFAHMICGWIOSXEEYÑOSRUTEXCALKNYANUYDUNEMVMESGNQUKZABXCCASMESVCRAJJREYYNEYKANG'
    # dictionary_text = 'ABCDEFGHIJKLMNÑOPQRSTUVWXYZ'
    # hash_text = '5442d541845e30ef6af885af537d41d35b2fa5e21fb47a5eae98043c441362e1'
    
    asdf = hack_vigenere(proccessed_text, dictionary_text, hash_text)
    print(asdf)
    
def get_key_lengths(ciphertext):
    # Find out the sequences of 3 to 6 letters that occur multiple times
    # in the ciphertext. repeated_sequences_spacings has a value like:
    # {'EXG': [192], 'NAF': [339, 972, 633], ... }
    repeated_sequences_spacings = get_repeated_sequences_spacings(ciphertext)

    # See get_most_common_factors() for a description of seq_factors.
    seq_factors = {}
    for seq in repeated_sequences_spacings:
        seq_factors[seq] = []
        for spacing in repeated_sequences_spacings[seq]:
            seq_factors[seq].extend(get_useful_factors(spacing))

    # See get_most_common_factors() for a description of factors_by_count.
    factors_by_count = get_most_common_factors(seq_factors)

    # Now we extract the factor counts from factors_by_count and
    # put them in all_likely_key_lenghts so that they are easier to
    # use later.
    all_likely_key_lengths = []
    for (factor, count) in factors_by_count:
        all_likely_key_lengths.append(factor)

    return all_likely_key_lengths

def get_useful_factors(num):
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
    
def get_most_common_factors(seq_factors):
    # First, get a count of how many times a factor occurs in seq_factors.
    factor_counts = {} # key is a factor, value is how often if occurs

    # seq_factors keys are sequences, values are lists of factors of the
    # spacings. seq_factors has a value like: {'GFD': [2, 3, 4, 6, 9, 12,
    # 18, 23, 36, 46, 69, 92, 138, 207], 'ALW': [2, 3, 4, 6, ...], ...}
    for seq in seq_factors:
        factor_list = seq_factors[seq]
        for factor in factor_list:
            if factor not in factor_counts:
                factor_counts[factor] = 0
            factor_counts[factor] += 1

    # Second, put the factor and its count into a tuple, and make a list
    # of these tuples so we can sort them.
    factors_by_count = []
    for factor in factor_counts:
        # exclude factors larger than MAX_KEY_LENGTH
        if factor <= MAX_KEY_LENGTH:
            # factors_by_count is a list of tuples: (factor, factorCount)
            # factors_by_count has a value like: [(3, 497), (2, 487), ...]
            factors_by_count.append((factor, factor_counts[factor]))

    # Sort the list by the factor count.
    factors_by_count.sort(key=lambda x: x[1], reverse=True)

    return factors_by_count

def get_repeated_sequences_spacings(proccessed_text):
    # dict de secuencias {secuencia, [lista espacios entre secuencias]}
    sequences_spacings = {}
    for sequence_len in range(3, 7):
        for seq_start in range(len(proccessed_text) - sequence_len):
            # Determine what the sequence is, and store it in seq
            seq = proccessed_text[seq_start:seq_start + sequence_len]
            # Look for this sequence in the rest of the message
            for i in range(seq_start + sequence_len, len(proccessed_text) - sequence_len):
                if proccessed_text[i:i + sequence_len] == seq:
                    if seq not in sequences_spacings:
                        sequences_spacings[seq] = []
                    # Metemos en la lista de espacios la diferencia entre cada secuencia.
                    sequences_spacings[seq].append(i - seq_start)
    return sequences_spacings

def hack_vigenere(ciphertext, dictionary, hash_text):
    # Likely key lenghts
    all_likely_key_lenghts = get_key_lengths(ciphertext)

    for key_length in all_likely_key_lenghts:
        print('Attempting with key length {}...'.format(key_length))
        key = attempt_hack_with_key_length(ciphertext, key_length, dictionary, hash_text)
        if (key != None):
            return key

def attempt_hack_with_key_length(ciphertext, most_likely_key_length, dictionary, hash_text):
    for combination in itertools.product(dictionary, repeat=most_likely_key_length):
        key = ''.join(combination)
        print(key)
        decrypted_text = decrypt(ciphertext, key, dictionary)
        hashed_message = hashlib.sha256(decrypted_text.encode('utf-8')).hexdigest()
        if (hashed_message == hash_text):
            return key

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
