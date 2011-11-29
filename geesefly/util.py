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

"""Various helper functions for handling arrays, etc."""

import struct
from operator import xor

words = list
bytelist = tuple
bigint = long

# working out some differences between Python 2 and 3
try:
    from itertools import imap, izip
except ImportError:
    imap = map
    izip = zip
try:
    reduce
except NameError:
    from functools import reduce
try:
    xrange = xrange
except:
    xrange = range

max64 = 0xffffffffffffffff

SKEIN_KS_PARITY = 0x5555555555555555

# zeroed out byte string and list for convenience and performance
zero_bytes = struct.pack('64B', *[0] * 64)
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
    """Return a list of `length` 64-bit words from `data`.
    
    `data` must consist of `length` * 8 bytes.
    `length` must be 1, 2, or 8.

    """
    return list(words_format[length].unpack(data))

def words2bytes(data, length=8):
    """Return a `length` * 8 byte string from `data`.


    `data` must be a list of `length` 64-bit words
    `length` must be 1, 2, or 8.

    """
    return words_format[length].pack(*data)
        
def RotL_64(x, N):
    """Return `x` rotated left by `N`.""" 
    return (x << (N & 63)) & max64 | (x >> ((64-N) & 63))

def RotR_64(x, N):
    """Return `x` rotated right by `N`.""" 
    return ((x >> (N & 63)) | (x << ((64-N) & 63))) & max64

def add64(a,b):
    """Return a 64-bit integer sum of `a` and `b`."""
    return (a + b) & max64

def sub64(a,b):
    """Return a 64-bit integer difference of `a` and `b`."""
    return (a - b) & max64


