# /usr/bin/env python
# coding=utf-8

#  Copyright 2010 Jonathan Bowman
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
#  implied. See the License for the specific language governing
#  permissions and limitations under the License.

"""Functions for en/decrypting variable-length messages"""

import operator
import struct
import zlib

from .threefish import (bytes2words, imap, Threefish512, words2bytes,
                        xrange)
from .skein import (empty_bytes, Skein512, Skein512Random)

class AuthenticationError(Exception):
    pass

# The following will be used as a prefix for ciphertext encoded with the
# encrypt function. The "encode" method is used so that it will be a
# bytestring whether we are using Python 2 or 3
ciphertext_prefix = '___ciphertext___'.encode()

def encrypt(data, key):
    """Return ciphertext, encrypting `data` with `key`.

    Both `data` and `key` may be of arbitrary length.

    If `data` begins with the string "___ciphertext___", a decryption
    process will occur instead of encryption.

    Example:

    >>> from binascii import b2a_hex
    >>> from string import printable
    >>> plaintext = printable
    >>> ciphertext = geesefly.encrypt(plaintext, "spam") 
    >>> b2a_hex(ciphertext)
    '5f5f5f636970686572746578745f5f5f58ece52585ce261ecf6542bc20e1452d0ff1fe705afdec666a832aafb427748e159408731760a7a0a8ce8b58354b085056453d63c3b2784d769ec6041e8497f73769836eb87d0751899f2e8c055e7d5e40b8ece330e5111af44ebc8c252e419eda7f9a02c36407ca261fef42a685c477ad7be59abbd57bd69f7c2065d449d0ac8791313fe005c0d975921bb2d3f4bb92'
    >>> geesefly.encrypt(ciphertext, "spam")
    \'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\\\'()*+,-./:;<=>?@[\\\\]^_`{|}~ \\t\\n\\r\\x0b\\x0c0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\\\'()*+,-./:;<=>?@[\\\\]^_`{|}~ \\t\\n\\r\\x0b\\x0c...\'

    """
    if data.startswith(ciphertext_prefix):
        encrypt = False
        salt = data[16:32]
        data = data[32:]
    else:
        encrypt = True
        salt = Skein512Random().getbytes(16)

    hashed = Skein512(msg=key, digest_bits=1024, key=salt,
                      block_type='nonce').final()
    key = hashed[:64]
    iv = hashed[64:]
    tf = Threefish512(key)
    
    previous_block = bytes2words(iv)
    if encrypt:
        output = ciphertext_prefix + salt
        blocks, remainder = divmod(len(data), 64)
        for block in (bytes2words(data[i*64:(i+1)*64])
                      for i in xrange(blocks)):
            previous_block = tf.encrypt_block(list(imap(operator.xor,
                                                        previous_block,
                                                        block)))
            output += words2bytes(previous_block)

        pad_val = 64 - remainder
        pad = struct.pack("B", pad_val) * pad_val
        if remainder:
            pad = data[-remainder:] + pad
        block = list(imap(operator.xor, previous_block,
                          bytes2words(pad)))
        output += words2bytes(tf.encrypt_block(block))
    else:
        output = empty_bytes
        for block in (bytes2words(data[i*64:(i+1)*64])
                      for i in xrange(len(data)//64)):
            output += words2bytes(list(imap(operator.xor,
                                            previous_block,
                                            tf.decrypt_block(block))))
            previous_block = block

        output = output.rstrip(output[-1:])

    return output

def compress_encrypt_auth(data, key):
    """Return ciphertext, compressing then encrypting `data` with `key`.

    The compressed/encrypted message is also authenticated using a key
    derived from `key`, but not the same key as used to encrypt the
    data.

    Both `data` and `key` may be of arbitrary length.

    If `data` begins with the string "___ciphertext___", a decryption
    process will occur instead of encryption.

    Example:

    >>> from binascii import b2a_hex
    >>> from string import printable
    >>> plaintext = printable * 100 # a long string
    >>> ciphertext = geesefly.compress_encrypt_auth(plaintext, "spam") 
    >>> b2a_hex(ciphertext)
    '5f5f5f636970686572746578745f5f5fca728d3d673166f7a3de5fc6e4759e325547220be0f9f6db7110dcf4ee7aa49e2b8be9aad96a8daf5fba4fa2f8fa4e57c8a59744d581102e75d2166f2d4ec6b1603c3b42ab9646a5f52c4676927c1cf60dd49e8823ef1a47d122b4b6bbd55b5dc260c0499e06b1202ed229c1ab56bd4cbbb3bca9adc2ef3be019585783d6f15893de3cae3355c245d2c9114131955c83739fb705db0d2889002ed295a21402779e8ff85673e47d4fe79087ecc9db8336825f9a26f0149fec21d06ba3e04d0057b4e7503264a6d06ddcee7070bec4ad0656fa9912df9f06050050ac7d5bfadc930d38000d438c5f4fb524238ca9a2731bc2c9fd2c99bd4e1d1a73e9a39e7e21a36cc95b1ee105b7644d094862f6ff9915'
    >>> geesefly.compress_encrypt_auth(ciphertext, "spam")
    \'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\\\'()*+,-./:;<=>?@[\\\\]^_`{|}~ \\t\\n\\r\\x0b\\x0c\'

    Compression is done with zlib. This is a particularly useful
    function with long messages, and may compensate to some degree for
    the performance problems of geesefly.py.

    """
    if data.startswith(ciphertext_prefix):
        encrypt = False
        received_mac = data[16:80]
        salt = data[80:96]
        data = data[96:]
    else:
        encrypt = True
        salt = Skein512Random().getbytes(16)
        data = zlib.compress(data)

    hashed = Skein512(msg=key, digest_bits=1280, key=salt,
                      block_type='nonce').final()
    key = hashed[:64]
    iv = hashed[64:128]
    mac_key = hashed[128:]
    tf = Threefish512(key)

    previous_block = bytes2words(iv)
    if encrypt:
        output = empty_bytes
        blocks, remainder = divmod(len(data), 64)
        for block in (bytes2words(data[i*64:(i+1)*64])
                      for i in xrange(blocks)):
            previous_block = tf.encrypt_block(list(imap(operator.xor,
                                                        previous_block,
                                                        block)))
            output += words2bytes(previous_block)

        pad_val = 64 - remainder
        pad = struct.pack("B", pad_val) * pad_val
        if remainder:
            pad = data[-remainder:] + pad
        block = list(imap(operator.xor, previous_block,
                          bytes2words(pad)))
        output += words2bytes(tf.encrypt_block(block))
        output = ciphertext_prefix +  Skein512(msg=output, key=mac_key).final() + salt + output

    else:
        if received_mac != Skein512(msg=data, key=mac_key).final():
            raise AuthenticationError
        output = empty_bytes
        for block in (bytes2words(data[i*64:(i+1)*64])
                      for i in xrange(len(data)//64)):
            output += words2bytes(list(imap(operator.xor,
                                            previous_block,
                                            tf.decrypt_block(block))))
            previous_block = block

        output = zlib.decompress(output.rstrip(output[-1:]))

    return output
