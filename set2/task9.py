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
    

assert pkcs7_pad(b'YELLOW SUBMARINE', 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04'

print("Task 9 successful!")