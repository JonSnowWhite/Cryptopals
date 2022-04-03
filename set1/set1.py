import base64
from Crypto.Cipher import AES

## Code
# task 1

def hex_to_bytes(x: str):
    return bytes.fromhex(x)

def bytes_to_hex(x: bytes):
    return x.hex()

def bytes_to_base64(x: bytes):
    return base64.b64encode(x).decode('UTF-8')

def base64_to_bytes(x: str):
    return base64.b64decode(x)

def h_b(x):
    return hex_to_bytes(x)

def b_h(x):
    return bytes_to_hex(x)

def b_b64(x):
    return bytes_to_base64(x)

def b64_b(x):
    return base64_to_bytes(x)

# task 2

def xor(a: str, b: str):
    a, b = h_b(a), h_b(b)
    return b_h(bytes(a ^ b for a, b in zip(a, b)))

def xor_bytes(a: str, b: str):
    return b_h(bytes(a ^ b for a, b in zip(a, b)))

# task 3 single byte xor

def get_score(x: bytes):
    letters = 'bcdfghjklmnpqrsuvwxyz'
    better_letters = 'etoia '
    score = 0
    for byte in x.lower():
        if chr(byte) in letters:
            score += 1
        if chr(byte) in better_letters:
            score += 3
    return score

def single_byte_xor_str(a: str):
    res1, res2 = single_byte_xor(h_b(a))
    return res1.decode("ASCII"), res2

def single_byte_xor(a: bytes):
    max_score = 0
    final_plaintext = ''
    for i in range(2**8):
        plaintext = bytes(i ^ x for x in a)
        score = get_score(plaintext)
        if score > max_score:
            final_plaintext = plaintext
            max_score = score
    return final_plaintext, max_score

# task 4 detect single byte xor

def detect_single_byte_xor(path: str):
    with open(path, 'r') as ciphers:
        max_score = 0
        final_plaintext = ''
        for cipher in ciphers:
            try:
                plaintext, score =  single_byte_xor_str(cipher.strip())
                if score > max_score:
                    final_plaintext = plaintext
                    max_score = score
            except:
                # just pass whatever is not parseable with utf-8
                pass
    return final_plaintext
    
# task 5

def repeating_xor(m: str, key: str):
    m = m.encode('ASCII')
    _key = ''
    for x in range(len(m)):
        _key += key[x % 3]
    key = _key.encode('ASCII')
    return xor_bytes(m, key)

# task 6

def get_bytes_from_file(path: str):
    with open(path) as file:
        return b64_b(file.read())



def hamming_distance(a: bytes, b: bytes, normalized=False) -> int:
    distance = 0
    for byte1, byte2 in zip(a,b):
        # xor bytes and count 1's
        _xor = byte1 ^ byte2
        # and with last bit and shift to right to count 1's
        while _xor > 0:
            if _xor & 1 == 1:
                distance += 1
            _xor >>= 1
    # to compare distances of bytes with different lengths we gotta normalize the results
    if normalized:
        return distance/len(a)
    else:
        return distance

def score_key_length(cipher: bytes, key_length: int):
    score = 0
    blocks = len(cipher) // (2*key_length)
    for i in range(blocks):
        # wild slicing to get two blocks
        block1 = cipher[2*i*key_length:2*i*key_length+key_length]
        block2 = cipher[2*i*key_length+key_length:2*i*key_length+2*key_length]
        score += hamming_distance(block1, block2, normalized=True)
    # normalize overall score by amount of blocks we considered
    return score / blocks

def get_probable_key_lengths(cipher: bytes, max_length: int):
    key_lengths_distances = []
    # iterate over key lengths
    for length in range(2, max_length):
        # [key_length, weighted_hamming_distance]
        key_lengths_distances.append([length, score_key_length(cipher, length)])
    # sort by distance and return key_lengths with lowest distance
    return sorted(key_lengths_distances, key=lambda x:x[1])[0][0]

def break_repeating_xor(cipher_file: str):
    cipher = get_bytes_from_file(cipher_file)
    block_length = get_probable_key_lengths(cipher, 40)

    # convert ciphertext to block solvable by single byte xor
    blocks = block_length * [b'']
    for index in range(len(cipher)):
        blocks[index % block_length] = blocks[index % block_length] + cipher[index:index+1]
    blocks = [single_byte_xor(block)[0] for block in blocks]

    # convert back to single byte array
    result = b''
    for index in range(len(cipher)):
        result += blocks[index % len(blocks)][0:1]
        blocks[index % len(blocks)] = blocks[index % len(blocks)][1:]
    return result

# task 7

def task7():
    with open('set1/data/aes_ecb.txt') as file:
        return decrypt_aes_cbc(b64_b(file.read()), "YELLOW SUBMARINE".encode('ASCII')).decode('ASCII')

def decrypt_aes_cbc(cipher: bytes, key: bytes):
    BLOCK_LENGTH = 128
    alg = AES.new(key, AES.MODE_ECB)
    return alg.decrypt(cipher)

# task 8

def task8():
    with open('set1/data/break_aes_ecb.txt') as file:
        for i, line in enumerate(file):
            if detect_aes_ecb(b64_b(line)):
                return i, line

def detect_aes_ecb(cipher: bytes) -> bool:
    BLOCK_LENGTH = 16
    blocks = []
    for i in range(len(cipher)//BLOCK_LENGTH):
        blocks.append(cipher[i*BLOCK_LENGTH:i*BLOCK_LENGTH+BLOCK_LENGTH])
    for i, block1 in enumerate(blocks):
        for j, block2 in enumerate(blocks):
            if i == j:
                continue
            if block1 == block2:
                return True
    return False


## Execute
# task 1
assert bytes_to_base64(hex_to_bytes('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')) == 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

# task 2
assert xor('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965') == '746865206b696420646f6e277420706c6179'

# task 3
assert single_byte_xor_str('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')[0] == 'Cooking MC\'s like a pound of bacon'

# task 4
assert detect_single_byte_xor('set1/data/detect_single_byte_xor.txt') == 'Now that the party is jumping\n'

# task 5
m = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
assert repeating_xor(m, 'ICE') == '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'

# task 6
assert hamming_distance('this is a test'.encode('ASCII'), 'wokka wokka!!!'.encode('ASCII')) == 37
assert break_repeating_xor('set1/data/break_repeating_xor.txt').decode('ASCII').startswith("I'm back and I'm ringin' the bell")

# task 7
assert task7().startswith("I'm back and I'm ringin' the bell")

# task8
assert task8()[0] == 132 # this line is ecb mode