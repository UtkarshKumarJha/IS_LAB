# pure_des.py
# Pure-Python DES (ECB mode), no external crypto libraries.
# Note: educational implementation; not optimized for speed.

from typing import List

# ===================== DES tables (standard) =====================
# All permutation tables are 1-based positions.

IP = [
 58, 50, 42, 34, 26, 18, 10, 2,
 60, 52, 44, 36, 28, 20, 12, 4,
 62, 54, 46, 38, 30, 22, 14, 6,
 64, 56, 48, 40, 32, 24, 16, 8,
 57, 49, 41, 33, 25, 17, 9, 1,
 59, 51, 43, 35, 27, 19, 11, 3,
 61, 53, 45, 37, 29, 21, 13, 5,
 63, 55, 47, 39, 31, 23, 15, 7
]

FP = [  # final permutation = inverse IP
 40, 8, 48, 16, 56, 24, 64, 32,
 39, 7, 47, 15, 55, 23, 63, 31,
 38, 6, 46, 14, 54, 22, 62, 30,
 37, 5, 45, 13, 53, 21, 61, 29,
 36, 4, 44, 12, 52, 20, 60, 28,
 35, 3, 43, 11, 51, 19, 59, 27,
 34, 2, 42, 10, 50, 18, 58, 26,
 33, 1, 41, 9, 49, 17, 57, 25
]

E = [  # expansion 32->48
 32, 1, 2, 3, 4, 5,
 4, 5, 6, 7, 8, 9,
 8, 9, 10, 11, 12, 13,
 12, 13, 14, 15, 16, 17,
 16, 17, 18, 19, 20, 21,
 20, 21, 22, 23, 24, 25,
 24, 25, 26, 27, 28, 29,
 28, 29, 30, 31, 32, 1
]

S_BOX = [
 # S1
 [
  [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
  [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
  [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
  [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]
 ],
 # S2
 [
  [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
  [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
  [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
  [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]
 ],
 # S3
 [
  [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
  [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
  [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
  [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]
 ],
 # S4
 [
  [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
  [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
  [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
  [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]
 ],
 # S5
 [
  [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
  [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
  [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
  [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]
 ],
 # S6
 [
  [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
  [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
  [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
  [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]
 ],
 # S7
 [
  [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
  [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
  [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
  [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]
 ],
 # S8
 [
  [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
  [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
  [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
  [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]
 ]
]

P = [
 16,7,20,21,29,12,28,17,
 1,15,23,26,5,18,31,10,
 2,8,24,14,32,27,3,9,
 19,13,30,6,22,11,4,25
]

PC1 = [
 57,49,41,33,25,17,9,
 1,58,50,42,34,26,18,
 10,2,59,51,43,35,27,
 19,11,3,60,52,44,36,
 63,55,47,39,31,23,15,
 7,62,54,46,38,30,22,
 14,6,61,53,45,37,29,
 21,13,5,28,20,12,4
]

PC2 = [
 14,17,11,24,1,5,
 3,28,15,6,21,10,
 23,19,12,4,26,8,
 16,7,27,20,13,2,
 41,52,31,37,47,55,
 30,40,51,45,33,48,
 44,49,39,56,34,53,
 46,42,50,36,29,32
]

# left shifts for each round
SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

# ===================== utilities: bits/bytes/permutations =====================

def bytes_to_bitlist(b: bytes) -> List[int]:
    bits = []
    for byte in b:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits  # MSB first

def bitlist_to_bytes(bits: List[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        out.append(byte)
    return bytes(out)

def permute(bits: List[int], table: List[int]) -> List[int]:
    # table is 1-based
    return [bits[i - 1] for i in table]

def left_shift(bits: List[int], n: int) -> List[int]:
    return bits[n:] + bits[:n]

# ===================== key schedule =====================

def generate_round_keys(key8: bytes) -> List[List[int]]:
    # key8: 8 bytes
    key_bits = bytes_to_bitlist(key8)  # 64 bits
    # apply PC-1 => 56 bits
    permuted = permute(key_bits, PC1)
    C = permuted[:28]
    D = permuted[28:]
    round_keys = []
    for shift in SHIFTS:
        C = left_shift(C, shift)
        D = left_shift(D, shift)
        CD = C + D
        K = permute(CD, PC2)  # 48 bits
        round_keys.append(K)
    return round_keys  # 16 keys, each 48-bit list

# ===================== round function (F) =====================

def sbox_substitution(bits48: List[int]) -> List[int]:
    out32 = []
    assert len(bits48) == 48
    for i in range(8):
        block = bits48[i*6:(i+1)*6]
        row = (block[0] << 1) | block[5]
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
        val = S_BOX[i][row][col]
        # append 4-bit value
        for k in range(3, -1, -1):
            out32.append((val >> k) & 1)
    return out32

def feistel(R: List[int], K48: List[int]) -> List[int]:
    # R: 32 bits list
    # 1) expand to 48
    R_exp = permute(R, E)
    # 2) XOR with key
    xor48 = [r ^ k for r, k in zip(R_exp, K48)]
    # 3) S-box substitution to 32 bits
    s_out = sbox_substitution(xor48)
    # 4) P permutation
    return permute(s_out, P)

# ===================== single-block DES encrypt/decrypt =====================

def des_block_encrypt(block8: bytes, round_keys: List[List[int]]) -> bytes:
    bits = bytes_to_bitlist(block8)
    bits = permute(bits, IP)
    L = bits[:32]
    R = bits[32:]
    for i in range(16):
        F = feistel(R, round_keys[i])
        newR = [l ^ f for l, f in zip(L, F)]
        L = R
        R = newR
    preoutput = R + L  # note swap
    final = permute(preoutput, FP)
    return bitlist_to_bytes(final)

def des_block_decrypt(block8: bytes, round_keys: List[List[int]]) -> bytes:
    # same as encrypt but use keys in reverse
    bits = bytes_to_bitlist(block8)
    bits = permute(bits, IP)
    L = bits[:32]
    R = bits[32:]
    for i in range(15, -1, -1):
        F = feistel(R, round_keys[i])
        newR = [l ^ f for l, f in zip(L, F)]
        L = R
        R = newR
    preoutput = R + L
    final = permute(preoutput, FP)
    return bitlist_to_bytes(final)

# ===================== simple PKCS#5 padding (block size 8) =====================

def pkcs5_pad(data: bytes, block_size: int = 8) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs5_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]

# ===================== ECB mode encrypt/decrypt =====================

def des_encrypt_ecb(plaintext: bytes, key8: bytes) -> bytes:
    if len(key8) != 8:
        raise ValueError("Key must be 8 bytes")
    round_keys = generate_round_keys(key8)
    pt_padded = pkcs5_pad(plaintext, 8)
    cipher = bytearray()
    for i in range(0, len(pt_padded), 8):
        block = pt_padded[i:i+8]
        cipher_block = des_block_encrypt(block, round_keys)
        cipher.extend(cipher_block)
    return bytes(cipher)

def des_decrypt_ecb(ciphertext: bytes, key8: bytes) -> bytes:
    if len(key8) != 8:
        raise ValueError("Key must be 8 bytes")
    round_keys = generate_round_keys(key8)
    plain = bytearray()
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        pt_block = des_block_decrypt(block, round_keys)
        plain.extend(pt_block)
    return pkcs5_unpad(bytes(plain))

# ===================== demo using provided key and message =====================

if __name__ == "__main__":
    key_text = "A1B2C3D4"   # exactly 8 ASCII characters -> 8 bytes
    key_bytes = key_text.encode('utf-8')

    message = "Confidential Data"
    pt = message.encode('utf-8')

    ct = des_encrypt_ecb(pt, key_bytes)
    print("Ciphertext (hex):", ct.hex().upper())

    recovered = des_decrypt_ecb(ct, key_bytes)
    print("Decrypted plaintext:", recovered.decode('utf-8'))
