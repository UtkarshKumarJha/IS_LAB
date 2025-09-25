# requires: pip install pycryptodome
import time
from Crypto.Cipher import DES, AES
from Crypto.Random import get_random_bytes

def pkcs5_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs5_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

# message
message = b"Performance Testing of Encryption Algorithms"

# --- DES ---
key_des = b"8bytekey"  # DES needs exactly 8 bytes
des = DES.new(key_des, DES.MODE_ECB)

pt_padded_des = pkcs5_pad(message, 8)

start = time.perf_counter()
ct_des = des.encrypt(pt_padded_des)
dec_des = pkcs5_unpad(des.decrypt(ct_des))
end = time.perf_counter()

des_time = end - start

# --- AES-256 ---
key_aes = get_random_bytes(32)  # 32 bytes = 256 bits
aes = AES.new(key_aes, AES.MODE_ECB)

pt_padded_aes = pkcs5_pad(message, 16)

start = time.perf_counter()
ct_aes = aes.encrypt(pt_padded_aes)
dec_aes = pkcs5_unpad(aes.decrypt(ct_aes))
end = time.perf_counter()

aes_time = end - start

# results
print("DES ciphertext (hex):", ct_des.hex())
print("DES decrypted:", dec_des.decode())

print("AES-256 ciphertext (hex):", ct_aes.hex())
print("AES-256 decrypted:", dec_aes.decode())

print("\nTiming results:")
print(f"DES total time: {des_time:.6f} seconds")
print(f"AES-256 total time: {aes_time:.6f} seconds")
