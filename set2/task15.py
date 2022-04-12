import unittest

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
    

assert pkcs7_unpad(b'YELLOW SUBMARINE\x04\x04\x04\x04') == b'YELLOW SUBMARINE'

# wonky exception test
try:
    pkcs7_unpad(b'YELLOW SUBMARINE\x04\x04\x04\x04')
    assert False
except:
    pass