#!/usr/bin/env python
# coding=utf-8

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__),'..'))

import geesefly

test_vectors = {
    struct.pack('B',0xff):
    '71b7bce6fe6452227b9ced6014249e5b'\
    'f9a9754c3ad618ccc4e0aae16b316cc8'\
    'ca698d864307ed3e80b6ef1570812ac5'\
    '272dc409b5a012df2a579102f340617a'.encode(),
    struct.pack('64B',*range(255,255-64,-1)):
    '45863ba3be0c4dfc27e75d358496f4ac'\
    '9a736a505d9313b42b2f5eada79fc17f'\
    '63861e947afb1d056aa199575ad3f8c9'\
    'a3cc1780b5e5fa4cae050e989876625b'.encode(),
    struct.pack('128B',*range(255,255-128,-1)):
    '91cca510c263c4ddd010530a33073309'\
    '628631f308747e1bcbaa90e451cab92e'\
    '5188087af4188773a332303e6667a7a2'\
    '10856f742139000071f48e8ba2a5adb7'.encode(),
}

if __name__ == "__main__":
    sys.stdout.write("\nChecking Skein512 test vectors:\n")
    for k,v in test_vectors.items():
        sys.stdout.write("    %d byte message... " % (len(k)))
        digest = geesefly.Skein512(k).hexdigest()
        if digest == v:
            sys.stdout.write("Success\n")
        else:
            sys.stdout.write("Fail\n")
            print(digest)


    key = "spam!".encode()
    plaintext = "Spam, Spam, Spam, Spam, Spam, Spam, baked beans, Spam, Spam, Spam and Spam!".encode()
    sys.stdout.write("\nChecking geesefly encryption routines:\n")
    sys.stdout.write("    Encryption/Decryption... ")
    result = geesefly.encrypt(plaintext, key)
    if geesefly.encrypt(result, key) == plaintext:
        sys.stdout.write("Success\n")
    else:
        sys.stdout.write("Fail\n")
    sys.stdout.write("    Compression/Encryption/Decryption/"\
                     "Authentication... ")
    result = geesefly.compress_encrypt_auth(plaintext, key)
    if geesefly.compress_encrypt_auth(result, key) == plaintext:
        sys.stdout.write("Success\n")
    else:
        sys.stdout.write("Fail\n")

