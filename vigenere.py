#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import itertools
import hashlib
import time
import logging
import collections

logger = logging.getLogger(__name__)

DEFAULT_MAX_KEY_LENGTH = 10
MAX_KEY_LENGTH = DEFAULT_MAX_KEY_LENGTH
CIPHERTEXT_SAMPLE_SIZE_FOR_SEQUENCES_COUNTING = 500
MOST_COMMON_SPANISH = ['E', 'A', 'O', 'S', 'R', 'N', 'I', 'D', 'L', 'C', 'T', 'U', 'M', 'P', 'B', 'G', 'V', 'Y', 'Q', 'H', 'F', 'Z', 'J', 'Ñ', 'X', 'K', 'W']
MOST_COMMON_ENGLISH = ['E', 'T', 'A', 'O', 'I', 'N', 'S', 'H', 'R', 'D', 'L', 'U', 'W', 'M', 'F', 'C', 'G', 'Y', 'P', 'B', 'K', 'V', 'J', 'X', 'Q', 'Z']

def main():
    parser = argparse.ArgumentParser(description='Hacking Vigenère cipher. Attempts to guess the key of a encrypted input and uses a hash of the uncrypted text to check if it was successful. A dictionary with the characters used in the text must be provided.', add_help=True)
    parser.add_argument('-i', '--input', metavar='INPUT', nargs='?', type=argparse.FileType(),
        help='Path for the input file', required=True)
    parser.add_argument('-d', '--dictionary', metavar='DICTIONARY', nargs='?', type=argparse.FileType(),
        help='Path for the dictionary file', required=True)
    parser.add_argument('--hash', metavar='HASH', nargs='?', type=argparse.FileType(),
        help='Path for the hash file', required=True)
    parser.add_argument('--max-key-length', metavar='max_key_length', type=int,
        default=DEFAULT_MAX_KEY_LENGTH, help='Maximum key length (default: %(default)s). Less is faster.')
    parser.add_argument('-v', '--verbose',  help='Be verbose',
        action='store_const', dest='loglevel', const=logging.INFO)
    parser.add_argument('--debug', help='Print lots of debugging statements',
        action='store_const', dest='loglevel', const=logging.DEBUG, default=logging.WARNING)
    args = parser.parse_args()

    logging.basicConfig(format='%(levelname)s: %(message)s', level=args.loglevel)

    global MAX_KEY_LENGTH
    MAX_KEY_LENGTH = args.max_key_length
    proccessed_text = args.input.read().strip()
    dictionary_text = args.dictionary.read().strip()
    hash_text = args.hash.read().strip()

    dictionary_char_to_index = {char: index for index, char in enumerate(dictionary_text)}
    dictionary_index_to_char = {index: char for index, char in enumerate(dictionary_text)}

    start_time = time.time()
    key = guess_key(proccessed_text, dictionary_text, dictionary_char_to_index, dictionary_index_to_char, hash_text)
    print('Successfully guessed key {} in {} seconds'.format(key, time.time() - start_time))

def guess_key(ciphertext, dictionary, dictionary_char_to_index, dictionary_index_to_char, hash_text):
    key_lenghts = get_key_lengths(ciphertext)
    logger.info('These are the key lengths guessed {}'.format(key_lenghts))

    for key_length in key_lenghts:

        logger.info('Attempting with key length of {}...'.format(key_length))
        key = guess_key_attempt_with_key_length(ciphertext, key_length, dictionary_char_to_index, dictionary_index_to_char, hash_text)
        if (key != None):
            return key
    return None

def guess_key_attempt_with_key_length(ciphertext, key_length, dictionary_char_to_index, dictionary_index_to_char, hash_text):
    probable_characters_every_row = []
    for i in range(key_length):
        ciphertext_sample = ciphertext
        col = ciphertext_sample[i::key_length]
        top_most_common_characters = [c for (c, _) in most_common_characters(col, 5)]
        logger.debug('most common of row {}: {}'.format(i, top_most_common_characters))
        most_common_character = most_common_characters(col, 1)[0][0]
        probable_characters = guess_probable_characters_from_most_common(most_common_character, key_length, dictionary_char_to_index, dictionary_index_to_char)
        probable_characters_every_row.append(probable_characters)

    logger.info('Probable characters for each key index are {}'.format(probable_characters_every_row))

    ciphertext_indexes = [dictionary_char_to_index.get(c) for c in ciphertext]
    ciphertext_lenght = len(ciphertext)
    dictionary_length = len(dictionary_char_to_index.keys())

    for combination in itertools.product(*probable_characters_every_row):
        key = ''.join(combination)
        logger.debug(key)
        decrypted_text = decrypt(ciphertext_indexes, ciphertext_lenght, key, dictionary_length, dictionary_char_to_index, dictionary_index_to_char)
        hashed_message = hashlib.sha256(decrypted_text.encode('utf-8')).hexdigest()
        if (hashed_message == hash_text):
            return key

def guess_probable_characters_from_most_common(character, key_length, dictionary_char_to_index, dictionary_index_to_char):
    dictionary_chars = dictionary_char_to_index.keys()
    dictionary_length = len(dictionary_chars)
    if 'Ñ' in dictionary_chars:
        MOST_COMMON = MOST_COMMON_SPANISH
    else:
        MOST_COMMON = MOST_COMMON_ENGLISH
    most_common_indexes = [dictionary_char_to_index.get(c) for c in MOST_COMMON[:5]]
    character_index = dictionary_char_to_index.get(character)
    probable_characters = []
    for i in most_common_indexes:
        j = (character_index - i) % dictionary_length
        probable_characters.append(dictionary_index_to_char.get(j))
    return probable_characters

def most_common_characters(text, count):
    return collections.Counter(text).most_common(count)

def get_key_lengths(ciphertext):
    '''
    Find out the sequences of 3 to 6 letters that occur multiple times
    in the ciphertext. repeated_sequences_spacings has a value like:
    {'EXG': [192], 'NAF': [339, 972, 633], ... }
    '''
    ciphertext_sample = ciphertext[:CIPHERTEXT_SAMPLE_SIZE_FOR_SEQUENCES_COUNTING]
    repeated_sequences_spacings = get_repeated_sequences_with_spacings(ciphertext_sample, 3, 6)

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
    key_lenghts = [k for (k, v) in sorted(factors_by_count.items(), key=lambda item: item[1], reverse=True)]

    logger.info(key_lenghts)
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
    '''
    Returns a list of useful factors of num. By 'useful' we mean factors
    less than MAX_KEY_LENGTH + 1. For example, get_useful_factors(144)
    returns [2, 72, 3, 48, 4, 36, 6, 24, 8, 18, 9, 16, 12]
    '''

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
def encrypt(plaintext, key, dictionary_char_to_index, dictionary_index_to_char):
    dictionary_length = len(dictionary_char_to_index.keys())
    key_length = len(key)
    key_indexes = [dictionary_char_to_index.get(c) for c in key]
    plaintext_indexes = [dictionary_char_to_index.get(c) for c in plaintext]
    ciphertext = ''
    for i in range(len(plaintext_indexes)):
        value = (plaintext_indexes[i] + key_indexes[i % key_length]) % dictionary_length
        ciphertext += dictionary_index_to_char.get(value)
    return ciphertext

def decrypt(ciphertext_indexes, ciphertext_length, key, dictionary_length, dictionary_char_to_index, dictionary_index_to_char):
    key_length = len(key)
    key_indexes = [dictionary_char_to_index.get(c) for c in key]
    plaintext = ''
    for i in range(ciphertext_length):
        value = (ciphertext_indexes[i] - key_indexes[i % key_length]) % dictionary_length
        plaintext += dictionary_index_to_char.get(value)
    return plaintext

if __name__ == '__main__':
    main()
