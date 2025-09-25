# requires: pip install pycryptodome
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

# key must be 16 or 24 bytes
key_hex = "1234567890ABCDEF23456789ABCDEF01A1B2C3D4E5F60718"
key = bytes.fromhex(key_hex)

plaintext = b"Classified Text"

# Create Triple DES cipher (ECB mode for simplicity)
cipher = DES3.new(key, DES3.MODE_ECB)

# Encrypt
ciphertext = cipher.encrypt(pad(plaintext, 8))
print("Ciphertext (hex):", ciphertext.hex())

# Decrypt
cipher2 = DES3.new(key, DES3.MODE_ECB)
decrypted = unpad(cipher2.decrypt(ciphertext), 8)
print("Decrypted text:", decrypted.decode())
