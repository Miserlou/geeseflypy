# coding=utf-8

from skein import *
import operator

ciphertext_prefix = '___ciphertext___'.encode()

def encrypt(data, key):
    if data.startswith(ciphertext_prefix):
        encrypt = False
        salt = data[16:32]
        data = data[32:]
    else:
        encrypt = True
        salt = Skein512Random().getbytes(16)

    hashed = Skein512(msg=key, digest_bits=1024, key=salt, block_type='nonce').final()
    key = hashed[:64]
    iv = hashed[64:]
    tf = Threefish512(key)
    
    previous_block = bytes2words(iv)
    if encrypt:
        output = ciphertext_prefix + salt
        blocks, remainder = divmod(len(data), 64)
        for block in (bytes2words(data[i*64:(i+1)*64]) for i in xrange(blocks)):
            previous_block = tf.encrypt_block(list(imap(operator.xor, previous_block, block)))
            output += words2bytes(previous_block)

        pad_val = 64 - remainder
        pad = struct.pack("B", pad_val) * pad_val
        if remainder:
            pad = data[-remainder:] + pad
        block = list(imap(operator.xor, previous_block, bytes2words(pad)))
        output += words2bytes(tf.encrypt_block(block))
    else:
        output = ''.encode()
        for block in (bytes2words(data[i*64:(i+1)*64]) for i in xrange(len(data)//64)):
            output += words2bytes(list(imap(operator.xor, previous_block, tf.decrypt_block(block))))
            previous_block = block

        output = output.rstrip(output[-1:])

    return output
