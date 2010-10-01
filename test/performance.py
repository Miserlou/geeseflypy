#!/usr/bin/env python
# coding=utf-8

# This code adapted form the work of Hagen Fürstenau

import os
import sys
import timeit

sys.path.insert(0, os.path.join(os.path.dirname(__file__),'..'))

COUNT = 3 
BLOCK_SIZE = 20 # KB

if __name__ == "__main__":
    setup = "from geesefly import Skein512\n"\
            "update = Skein512().update\n"\
            "txt = chr(0).encode() * %d\n" % BLOCK_SIZE*1024
    best = min(timeit.Timer("update(txt)", setup).repeat(
               number=COUNT, repeat=5))
    print("geesefly.Skein512 hashes %d KB/s on this machine"
          % COUNT*BLOCK_SIZE/best)
