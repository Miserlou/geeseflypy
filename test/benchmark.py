#!/usr/bin/env python
# coding=utf-8

import sys
import timeit

sys.path.insert(0, '..')

COUNT = 3 
BLOCK_SIZE = 20 # KB


def hashing_throughput(module, func, args=""):
    """Return performance in KB/s"""

    setup = "from %s import %s as hasher\n"\
            "update = hasher().update\n"\
            "txt = chr(0).encode() * %d"\
            % (module, func, BLOCK_SIZE*1024)
    #best = min(timeit.repeat("update(txt)", setup,
    best = min(timeit.Timer("update(txt)", setup).repeat(
               number=COUNT, repeat=5))
    return COUNT*BLOCK_SIZE/best


if __name__ == "__main__":
    hashers = [("hashlib", f)
               for f in ("md5", "sha1", "sha256", "sha512")]
    hashers += [("geesefly", 'Skein512')]
    for module, func in hashers:
        x = hashing_throughput(module, func)
        print("%s.%s: %d KB/s" % (module, func, x))
