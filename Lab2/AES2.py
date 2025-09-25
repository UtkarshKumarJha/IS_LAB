# aes_pure.py
# Pure Python AES-128 (ECB mode) with PKCS#7 padding.
# Educational; not optimized.

from typing import List

# AES parameters
NB = 4  # block size in 32-bit words (always 4 for AES)
NK = 4  # key length in 32-bit words (4 for AES-128)
NR = 10 # number of rounds for AES-128

SBOX = [
    # 256 values
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

INV_SBOX = [SBOX.index(i) for i in range(256)]

RCON = [
    0x00000000,
    0x01000000,0x02000000,0x04000000,0x08000000,
    0x10000000,0x20000000,0x40000000,0x80000000,
    0x1B000000,0x36000000
]

def sub_word(word: int) -> int:
    return ((SBOX[(word >> 24) & 0xFF] << 24) |
            (SBOX[(word >> 16) & 0xFF] << 16) |
            (SBOX[(word >> 8) & 0xFF] << 8) |
            (SBOX[word & 0xFF]))

def rot_word(word: int) -> int:
    return ((word << 8) & 0xFFFFFFFF) | ((word >> 24) & 0xFF)

def bytes_to_matrix(block: bytes) -> List[List[int]]:
    # column-major 4x4 matrix
    return [[block[row + 4*col] for col in range(4)] for row in range(4)]

def matrix_to_bytes(state: List[List[int]]) -> bytes:
    out = bytearray(16)
    for r in range(4):
        for c in range(4):
            out[r + 4*c] = state[r][c]
    return bytes(out)

def xor_words(a: int, b: int) -> int:
    return a ^ b

def key_expansion(key: bytes) -> List[int]:
    # Expand 16-byte key into 44 32-bit words (4*(Nr+1))
    assert len(key) == 16
    w = []
    # initial words
    for i in range(4):
        w.append(int.from_bytes(key[4*i:4*i+4], byteorder='big'))
    for i in range(4, 4*(NR+1)):
        temp = w[i-1]
        if i % 4 == 0:
            temp = sub_word(rot_word(temp)) ^ RCON[i//4]
        w.append(w[i-4] ^ temp)
    return w  # list of 44 integers

def add_round_key(state: List[List[int]], round_key_words: List[int]):
    # round_key_words: 4 words (32-bit) for the round
    for c in range(4):
        word = round_key_words[c]
        state[0][c] ^= (word >> 24) & 0xFF
        state[1][c] ^= (word >> 16) & 0xFF
        state[2][c] ^= (word >> 8) & 0xFF
        state[3][c] ^= word & 0xFF

def sub_bytes(state: List[List[int]]):
    for r in range(4):
        for c in range(4):
            state[r][c] = SBOX[state[r][c]]

def inv_sub_bytes(state: List[List[int]]):
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_SBOX[state[r][c]]

def shift_rows(state: List[List[int]]):
    # row r is rotated left by r bytes
    for r in range(1,4):
        state[r] = state[r][r:] + state[r][:r]

def inv_shift_rows(state: List[List[int]]):
    for r in range(1,4):
        state[r] = state[r][-r:] + state[r][:-r]

# Multiply in GF(2^8)
def xtime(a: int) -> int:
    return ((a << 1) & 0xFF) ^ (0x1B if (a & 0x80) else 0x00)

def mul(a: int, b: int) -> int:
    # Russian peasant multiplication in GF(2^8)
    res = 0
    for i in range(8):
        if b & 1:
            res ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B
        b >>= 1
    return res

def mix_single_column(col: List[int]) -> List[int]:
    a = col[:]  # copy
    res = [
        mul(a[0],2) ^ mul(a[1],3) ^ a[2] ^ a[3],
        a[0] ^ mul(a[1],2) ^ mul(a[2],3) ^ a[3],
        a[0] ^ a[1] ^ mul(a[2],2) ^ mul(a[3],3),
        mul(a[0],3) ^ a[1] ^ a[2] ^ mul(a[3],2)
    ]
    return [r & 0xFF for r in res]

def mix_columns(state: List[List[int]]):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mixed = mix_single_column(col)
        for r in range(4):
            state[r][c] = mixed[r]

def inv_mix_single_column(col: List[int]) -> List[int]:
    a = col[:]
    res = [
        mul(a[0],0x0e) ^ mul(a[1],0x0b) ^ mul(a[2],0x0d) ^ mul(a[3],0x09),
        mul(a[0],0x09) ^ mul(a[1],0x0e) ^ mul(a[2],0x0b) ^ mul(a[3],0x0d),
        mul(a[0],0x0d) ^ mul(a[1],0x09) ^ mul(a[2],0x0e) ^ mul(a[3],0x0b),
        mul(a[0],0x0b) ^ mul(a[1],0x0d) ^ mul(a[2],0x09) ^ mul(a[3],0x0e)
    ]
    return [r & 0xFF for r in res]

def inv_mix_columns(state: List[List[int]]):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mixed = inv_mix_single_column(col)
        for r in range(4):
            state[r][c] = mixed[r]

def encrypt_block(block: bytes, round_keys: List[int]) -> bytes:
    state = bytes_to_matrix(block)
    # initial round key
    add_round_key(state, round_keys[0:4])
    for rnd in range(1, NR):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[rnd*4:(rnd+1)*4])
    # final round
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[NR*4:(NR+1)*4])
    return matrix_to_bytes(state)

def decrypt_block(block: bytes, round_keys: List[int]) -> bytes:
    state = bytes_to_matrix(block)
    add_round_key(state, round_keys[NR*4:(NR+1)*4])
    for rnd in range(NR-1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[rnd*4:(rnd+1)*4])
        inv_mix_columns(state)
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0:4])
    return matrix_to_bytes(state)

# PKCS#7 padding (block size 16)
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % 16 != 0:
        raise ValueError("Invalid padded data")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]

# ECB mode
def aes_encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 requires 16-byte key")
    round_keys = key_expansion(key)
    # round_keys is list of 44 words; use by 4-word groups
    pt_padded = pkcs7_pad(plaintext, 16)
    ct = bytearray()
    for i in range(0, len(pt_padded), 16):
        ct.extend(encrypt_block(pt_padded[i:i+16], round_keys))
    return bytes(ct)

def aes_decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 requires 16-byte key")
    round_keys = key_expansion(key)
    pt = bytearray()
    for i in range(0, len(ciphertext), 16):
        pt.extend(decrypt_block(ciphertext[i:i+16], round_keys))
    return pkcs7_unpad(bytes(pt))

# Demo
if __name__ == "__main__":
    hex_key = "0123456789ABCDEF0123456789ABCDEF"
    key = bytes.fromhex(hex_key)  # 16 bytes
    message = "Sensitive Information"
    pt = message.encode("utf-8")

    ct = aes_encrypt_ecb(pt, key)
    print("Ciphertext (hex):", ct.hex().upper())

    recovered = aes_decrypt_ecb(ct, key)
    print("Decrypted:", recovered.decode("utf-8"))
