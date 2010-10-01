#!/usr/bin/env python
# coding=utf-8

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__),'..'))

import geesefly

test_vectors = {
    struct.pack('B',0xff):
    '42aa6bd9ca92e90ea28df6f6f2d0d9b85a2d1907ee4dc1b1'\
    '71ace7eb1159be3bd1bc56586d92492b6eff9be03306994c'\
    '65a332c4c24160f46655040e558e8329'.encode(),
    struct.pack('64B',*range(255,255-64,-1)):
    '04f96c6f61b3e237a4fa7755ee4acf34494222968954f495'\
    'ad147a1a715f7a73ebecfa1ef275bed87dc60bd1a0bc6021'\
    '06fa98f8e7237bd1ac0958e76d306678'.encode(),
    struct.pack('128B',*range(255,255-128,-1)):
    'b484ae9fb73e6620b10d52e49260ad26620db2883ebafa21'\
    '0d701922aca85368088144bdf4ef3d9898d47c34f130031b'\
    '0a0992f09f62dd78b329525a777daf7d'.encode(),
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

