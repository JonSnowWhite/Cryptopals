import os
import random
from Crypto.Cipher import AES

# from set 1

def xor_bytes(a: bytes, b: bytes):
    return bytes(a ^ b for a, b in zip(a, b))

# ecb mode from before

def encrypt_aes_ecb(message: bytes, key: bytes):
    # pad message
    message = pkcs7_pad(message, 16)
    alg = AES.new(key, AES.MODE_ECB)
    return alg.encrypt(message)

# cbc mode from before

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

def pkcs7_unpad(message: bytes):
    """
    Returns unpadded pkcs#7 message
    """
    padded_blocks = message[-1]
    if padded_blocks == 0:
        raise Exception("Zero padding is invalid")
    for i in range(1, padded_blocks+1):
        if message[-i] != padded_blocks:
            raise Exception("Padding is invalid")
    return message[:-padded_blocks]

# task 2

def encrypt_aes_cbc(message: bytes, iv: bytes, key: bytes):
    # pad message
    message = pkcs7_pad(message, 16)
    # iv holds the last ciphertext block
    iv = iv
    ciphertext = b''
    while len(message) > 0:
        # slice off plaintext block
        plain_block = message[:16]
        message = message[16:]
        # encrypt that block
        plain_block = xor_bytes(plain_block, iv)
        cipher_block = encrypt_aes_ecb(plain_block, key)
        # move block into iv and append to output
        iv = cipher_block
        ciphertext += cipher_block
    return ciphertext

# helper

def randbytes(x):
    return os.urandom(x)

def encryption_oracle(m):
    k = randbytes(16)
    x = randbytes(random.randint(5,10))
    y = randbytes(random.randint(5,10))
    m = x + m + y
    use_ecb = random.randint(0,1)
    if use_ecb == 1:
        return encrypt_aes_ecb(m, k), True
    else:
        iv = randbytes(16)
        return encrypt_aes_cbc(m, iv, k), False

def decider(encryption_oracle):
    is_ecb = True
    m = (11+16+16+11) * b'1'
    c, is_ecb_original = encryption_oracle(m)
    if c[16:32] != c[32:48]:
        is_ecb = False
    return is_ecb, is_ecb_original

for i in range(50):
    is_ecb, is_ecb_original = decider(encryption_oracle)
    assert is_ecb == is_ecb_original

print("Task 11 successful!")