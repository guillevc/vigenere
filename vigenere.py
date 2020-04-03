import os

dictionary_path = os.path.join(os.path.dirname(__file__), 'JdP_vigenere_alumnos_20200326\JdP_001_dictionary')

with open(dictionary_path) as f:
    for char in f.read():
        if char == '\n':
            break
        