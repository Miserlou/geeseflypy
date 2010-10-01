#!/usr/bin/env python
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

from __future__ import absolute_import

from .threefish import (bytes2words, Threefish512, words2bytes)
from .skein import (Skein512, Skein512Random)
from .geesefly import (compress_encrypt_auth, encrypt)

if __name__ == "__main__":
    data = struct.pack('64B',*range(255,255-64,-1))
    digest = Skein512(data).final()
    print("hash result:\n\t%s\n" % Skein512(data).hexdigest())

    key = "spam!".encode()
    plaintext = "Spam, Spam, Spam, Spam, Spam, Spam, baked beans, Spam, Spam, Spam and Spam!".encode()
    result = encrypt(plaintext, key)
    print(encrypt(result, key))
