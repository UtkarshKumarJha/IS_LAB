from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Plaintext
plaintext = b"Top Secret Data"

# AES-192 key (24 bytes)
key_hex = "FEDCBA9876543210FEDCBA9876543210"  # 16 bytes
key_bytes = bytes.fromhex(key_hex) + bytes.fromhex(key_hex[:16])[:8]  # extend to 24 bytes

# Pad plaintext to block size (16 bytes)
pt_padded = pad(plaintext, AES.block_size)

# Encrypt
cipher = AES.new(key_bytes, AES.MODE_ECB)
ciphertext = cipher.encrypt(pt_padded)
print("Ciphertext (hex):", ciphertext.hex().upper())

# Decrypt
decipher = AES.new(key_bytes, AES.MODE_ECB)
decrypted_padded = decipher.decrypt(ciphertext)
decrypted = unpad(decrypted_padded, AES.block_size)
print("Decrypted text:", decrypted.decode())
