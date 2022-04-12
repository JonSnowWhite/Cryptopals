import base64
from Crypto.Cipher import AES

# from set1

def base64_to_bytes(x: str):
    return base64.b64decode(x)

def b64_b(x):
    return base64_to_bytes(x)

def xor_bytes(a: bytes, b: bytes):
    return bytes(a ^ b for a, b in zip(a, b))

def decrypt_aes_ecb(cipher: bytes, key: bytes):
    alg = AES.new(key, AES.MODE_ECB)
    return alg.decrypt(cipher)

def encrypt_aes_ecb(cipher: bytes, key: bytes):
    alg = AES.new(key, AES.MODE_ECB)
    return alg.encrypt(cipher)

m = b'1234567890123456'
k =  b'6543210987654321'
assert decrypt_aes_ecb(encrypt_aes_ecb(m, k), k) == m

# from set2

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

def decrypt_aes_cbc(cipher: bytes, iv: bytes, key: bytes):
    if len(cipher) % 16 != 0:
        raise Exception("ciphertext length must be a multiple of 16")
    # iv holds the last ciphertext block
    iv = iv
    plaintext = b''
    while len(cipher) > 0:
        # slice off cipher block
        cipher_block = cipher[:16]
        cipher = cipher[16:]
        # decrypt that block
        plain_block = decrypt_aes_ecb(cipher_block, key)
        plain_block = xor_bytes(plain_block, iv)
        # update iv and append plain_block to plaintext
        iv = cipher_block
        plaintext += plain_block
    return pkcs7_unpad(plaintext)

def task10():
    with open('set2/data/task10.txt') as file:
        return decrypt_aes_cbc(b64_b(file.read()), bytes(16), b'YELLOW SUBMARINE').decode('ASCII')

# test

m = b'Very cool test string for encryption'
iv = b'1234567890123456'
k = b'6543210987654321'
assert decrypt_aes_cbc(encrypt_aes_cbc(m, iv, k), iv, k) == m

assert task10().startswith("I'm back and I'm ringin' the bell")
