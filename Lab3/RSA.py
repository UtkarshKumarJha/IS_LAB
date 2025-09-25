from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# --- Generate or define RSA keys ---
# You can generate new keys
key = RSA.generate(2048)

# Public key (n, e)
public_key = key.publickey()

# Private key (n, d)
private_key = key

# --- Prepare plaintext ---
plaintext = b"Asymmetric Encryption"

# --- Encryption with public key ---
cipher_rsa = PKCS1_OAEP.new(public_key)
ciphertext = cipher_rsa.encrypt(plaintext)
print("Ciphertext (hex):", ciphertext.hex())

# --- Decryption with private key ---
decipher_rsa = PKCS1_OAEP.new(private_key)
decrypted = decipher_rsa.decrypt(ciphertext)
print("Decrypted text:", decrypted.decode())
