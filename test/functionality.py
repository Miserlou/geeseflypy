#!/usr/bin/env python
# coding=utf-8

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__),'..'))

test_vectors = {
    struct.pack('B',0xff):
    '42aa6bd9ca92e90ea28df6f6f2d0d9b85a2d1907ee4dc1b171ace7eb1159be3bd1bc56586d92492b6eff9be03306994c65a332c4c24160f46655040e558e8329'.encode(),
    struct.pack('64B',*range(255,255-64,-1)):
    'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0'.encode(),
}

if __name__ == "__main__":
    data = struct.pack('64B',*range(255,255-64,-1))
    digest = Skein512(data).final()
    print("hash result:\n\t%s\n" % Skein512(data).hexdigest())

    key = "spam!".encode()
    plaintext = "Spam, Spam, Spam, Spam, Spam, Spam, baked beans, Spam, Spam, Spam and Spam!".encode()
    result = encrypt(plaintext, key)
    print(encrypt(result, key))
