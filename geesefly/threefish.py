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

import struct
from itertools import cycle, imap, izip

ROT = (46, 36, 19, 37,
       33, 27, 14, 42,
       17, 49, 36, 39,
       44,  9, 54, 56,
       39, 30, 34, 24,
       13, 50, 10, 17,
       25, 29, 39, 43,
        8, 35, 56, 22)

PERM = (0,1,2,3,4,5,6,7,
        2,1,4,7,6,5,0,3,
        4,1,6,3,0,5,2,7,
        6,1,0,7,2,5,4,3)

SKEIN_KS_PARITY = 0x5555555555555555

max64 = 0xffffffffffffffff

# zeroed out byte string and list for convenience and performance
zero_bytes = struct.pack('64B', [0] * 64)
zero_words = [0] * 8

# Build structs for conversion appropriate to this system, favoring
# native formats if possible for slight performance benefit
words_format_tpl = "%dQ"
if struct.pack('2B', 0, 1) == struct.pack('=H', 1): # big endian?
    words_format_tpl = "<" + words_format_tpl # force little endian
else:
    try: # is 64-bit integer native?
        struct.unpack(words_format_tpl % 2, zero_bytes[:16])
    except(struct.error): # Use standard instead of native
        words_format_tpl = "=" + words_format_tpl

# build structs for one-, two- and eight-word sequences
words_format = dict(
    (i,struct.Struct(words_format_tpl % i)) for i in (1,2,8))

def bytes2words(data, length=8):
    return list(words_format[length].unpack(data))

def words2bytes(data, length=8):
    return words_format[length].pack(*data)
        
def RotL_64(x, N):
    return (x << (N & 63)) & max64 | (x >> ((64-N) & 63))

def RotR_64(x, N):
    return ((x >> (N & 63)) | (x << ((64-N) & 63))) & max64

def xor64(a,b):
    return (a ^ b) & max64

def add64(a,b):
    return (a + b) & max64

def sub64(a,b):
    return (a - b) & max64

class Threefish512(object):
    def __init__(self, key=None, tweak=None):
        if key:
            self.key = bytes2words(key)
            self.prepare_key()
        else:
            self.key = zero_words[:] + [0]
        if tweak:
            self.tweak = bytes2words(tweak, 2)
            self.prepare_tweak()
        else:
            self.tweak = zero_words[:3]

    def prepare_key(self):
        final = xor64(reduce(xor64, self.key[:8]), SKEIN_KS_PARITY)
        try:
            self.key[8] = final
        except IndexError:
            self.key.append(final)

    def prepare_tweak(self):
        final =  xor64(self.tweak[0], self.tweak[1])
        try:
            self.tweak[2] = final
        except IndexError:
            self.tweak.append(final)

    def encrypt_block(self, plaintext):
        key = self.key
        tweak = self.tweak
        state = list(imap(add64, plaintext, key[:8]))
        state[5] = add64(state[5], tweak[0])
        state[6] = add64(state[6], tweak[1])

        for r,s in izip(xrange(1,19),cycle((0,16))):
            for i in xrange(16):
                m = PERM[2*i]
                n = PERM[2*i+1]
                state[m] = add64(state[m], state[n])
                state[n] = RotL_64(state[n], ROT[i+s])
                state[n] = xor64(state[n], state[m])
            for y in xrange(8):
                     state[y] = add64(state[y], key[(r+y) % 9])
            state[5] = add64(state[5], tweak[r % 3])
            state[6] = add64(state[6], tweak[(r+1) % 3])
            state[7] = add64(state[7], r)

        return state

    def feed_forward(self, state, plaintext):
        state[:] = list(imap(xor64, state, plaintext))

    def decrypt_block(self, ciphertext):
        key = self.key
        tweak = self.tweak
        state = ciphertext[:]

        for r,s in izip(xrange(18,0,-1),cycle((16,0))):
            for y in xrange(8):
                     state[y] = sub64(state[y], key[(r+y) % 9])
            state[5] = sub64(state[5], tweak[r % 3])
            state[6] = sub64(state[6], tweak[(r+1) % 3])
            state[7] = sub64(state[7], r)

            for i in xrange(15,-1,-1):
                m = PERM[2*i]
                n = PERM[2*i+1]
                state[n] = RotR_64(xor64(state[m],state[n]), ROT[i+s])
                state[m] = sub64(state[m], state[n])
        
        result = list(imap(sub64, state, key))
        result[5] = sub64(result[5], tweak[0])
        result[6] = sub64(result[6], tweak[1])
        return result
