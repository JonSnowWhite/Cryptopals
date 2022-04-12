import random
import os
import base64
from Crypto.Cipher import AES

# helper

def randbytes(x):
    return os.urandom(x)

def base64_to_bytes(x: str):
    return base64.b64decode(x)

def b64_b(x):
    return base64_to_bytes(x)

# ecb mode from before

def pkcs7_pad(message: bytes, block_length: int):
    """
    Returns pkcs7 padding of message padded to given length
    """
    if block_length >= 256:
        raise Exception("PKCS #7 padding only works for block length < 256")
    # determine how many blocks are missing in message to reach the block length
    blocks_to_pad = block_length - (len(message) % block_length)
    # we always pad, without missing blocks we pad a whole block_length
    if blocks_to_pad == 0:
        blocks_to_pad = block_length
    return message+bytes(blocks_to_pad*[blocks_to_pad])

def encrypt_aes_ecb(message: bytes, key: bytes):
    message = pkcs7_pad(message, 16)
    # pad message
    alg = AES.new(key, AES.MODE_ECB)
    return alg.encrypt(message)

RANDOM_STRING = b64_b("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
KEY = randbytes(16)

def encryption_oracle(m):
    global KEY
    global RANDOM_STRING
    return encrypt_aes_ecb(m + RANDOM_STRING, KEY)


def decrypt_random_string(encryption_oracle):
    ecb_test = encryption_oracle(32*b'A')
    if ecb_test[:16] != ecb_test[16:32]:
        print("Cipher is not ECB!")
        return b''
    len_m = len(encryption_oracle(b''))
    blocks = len_m // 16
    
    known_plaintext = b''
    compare = len_m * b'A'
    shift = len_m * b'A'

    for _ in range(len_m):
        # shift one byte into our last block that is not the random string
        shift = shift[:-1]
        next_byte = b''
        # try out all possible bytes
        for b in range(256):
            b_byte = b.to_bytes(1, 'big')
            compare = compare[:-1]
            compare += b_byte
            # encrypt
            c = encryption_oracle(compare + shift)
            enc_compare = c[:len_m]
            enc_shift = c[len_m:len_m*2]
            # if both the shifted and iterating blocks are the same we got the next byte
            if enc_compare == enc_shift:
                next_byte = b_byte
                break
        # update known plaintext and compare
        known_plaintext += next_byte
        compare = compare[1:] + b'A'
    return known_plaintext


assert decrypt_random_string(encryption_oracle).decode('ASCII').startswith("Rollin' in my 5.0")
print("Task 12 successful!")