geesefly.py is a pure Python implementation of the Skein hash function
and Threefish tweakable block cipher. It also includes a pseudo-random
number generator based on Skein, and Cipher-Block Chaining (CBC) based
functionality for encrypting variable-length data.

If you want a high-performance Python implementation of Skein and
Threefish, I highly recommend PySkein, available at: 

http://packages.python.org/pyskein/

In PySkein, the heavy lifting is done in compiled C, and hashes data
at a much faster rate than geesefly.py.

In contrast, this module is written in pure Python. While slow, it is
useful for applications where compiling a Python C extension is
unfeasible, such as Google's App Engine.

You also may find the geesefly.py code helpful in understanding Skein
and Threefish.

geesefly.py works with Python version 2.5 or later. This includes version 3
and up.
