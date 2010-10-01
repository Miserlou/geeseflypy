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
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import array
import binascii
import os
import struct

from .threefish import (add64, bytes2words, Threefish512,
                        words2bytes, words_format, zero_bytes,
                        zero_words)

try:
    xrange
except:
    xrange = range

# An empty bytestring that behaves itself whether in Python 2 or 3
empty_bytes = array.array('B').tostring()

class Skein512(object):
    block_size = 64
    block_bits = 512
    block_type = {'key':       0,
                  'nonce':     0x5400000000000000,
                  'msg':       0x7000000000000000,
                  'cfg_final': 0xc400000000000000,
                  'out_final': 0xff00000000000000}

    def __init__(self, msg='', digest_bits=512, key=None,
                 block_type='msg'):
        self.tf = Threefish512()
        if key:
            self.digest_bits = 512
            self.start_new_type('key')
            self.update(key)
            self.tf.key = bytes2words(self.final(False))
        self.digest_bits = digest_bits
        self.digest_size = (digest_bits + 7) >> 3
        self.start_new_type('cfg_final')
        b = words2bytes((0x133414853,digest_bits,0,0,0,0,0,0))
        self.process_block(b,32)
        self.start_new_type(block_type)
        if msg:
            self.update(msg)

    def start_new_type(self, block_type):
        self.buf = empty_bytes
        self.tf.tweak = [0, self.block_type[block_type]]

    def process_block(self, block, byte_count_add):
        for w in (bytes2words(block[i:i+64])
                  for i in xrange(0,len(block),64)):
            self.tf.tweak[0] = add64(self.tf.tweak[0], byte_count_add)
            self.tf.prepare_tweak()
            self.tf.prepare_key()
            self.tf.key = self.tf.encrypt_block(w)
            self.tf.feed_forward(self.tf.key, w)
            # set second tweak value to ~SKEIN_T1_FLAG_FIRST:
            self.tf.tweak[1] &= 0xbfffffffffffffff

    def update(self, msg):
        self.buf += msg
        buflen = len(self.buf)
        if buflen > 64:
            end = -(buflen % 64) or buflen
            data = self.buf[0:end]
            self.buf = self.buf[end:]
            self.process_block(data, 64)
        return self

    def final(self, output=True):
        self.tf.tweak[1] |= 0x8000000000000000 # SKEIN_T1_FLAG_FINAL
        buflen = len(self.buf)
        self.buf += zero_bytes[:64-buflen]
        self.process_block(self.buf, buflen)

        if not output:
            hash_val = words2bytes(self.tf.key)
        else:
            hash_val = empty_bytes
            self.buf = zero_bytes[:]
            key = self.tf.key[:] # temporary copy
            i=0
            while i*64 < self.digest_size:
                self.buf = words_format[1].pack(i) + self.buf[8:]
                self.tf.tweak = [0, self.block_type['out_final']]
                self.process_block(self.buf, 8)
                n = self.digest_size - i*64
                if n >= 64:
                    n = 64
                hash_val += words2bytes(self.tf.key)[0:n]
                self.tf.key = key
                i+=1
        return hash_val

    digest = final

    def hexdigest(self):
        return binascii.b2a_hex(self.digest())

class Skein512Random(Skein512):
    def __init__(self, seed=None, queue_size=512):
        Skein512.__init__(self, block_type='nonce')
        self.queue = []
        self.queue_size = queue_size
        self.tf.key = zero_words[:]
        if not seed:
          seed = os.urandom(100)
        self.reseed(seed)

    def reseed(self, seed):
        self.digest_size = 64
        self.update(words2bytes(self.tf.key) + seed)
        self.tf.key = bytes2words(self.final())

    def getbytes(self, request_bytes):
        self.digest_size = 64 + request_bytes
        self.update(words2bytes(self.tf.key))
        output = self.final()
        self.tf.key = bytes2words(output[0:64])
        return output[64:]

    def __iter__(self):
      return self

    def next(self):
      if not self.queue:
        self.queue = array.array('B', self.getbytes(self.queue_size))
      return self.queue.pop()
