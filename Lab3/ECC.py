from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# --- Generate ECC key pair ---
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# --- Message ---
plaintext = b"Secure Transactions"

# --- Encrypt using ephemeral key and AES session key ---
# Generate ephemeral key
ephemeral_key = ec.generate_private_key(ec.SECP256R1())
shared_secret = ephemeral_key.exchange(ec.ECDH(), public_key)

# Derive AES key from shared secret
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'ecc encryption'
).derive(shared_secret)

# Encrypt plaintext with AES-GCM
iv = os.urandom(12)
cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()
tag = encryptor.tag

print("Ciphertext (hex):", ciphertext.hex())

# --- Decrypt ---
# Receiver computes shared secret
shared_secret_recv = private_key.exchange(ec.ECDH(), ephemeral_key.public_key())
derived_key_recv = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'ecc encryption'
).derive(shared_secret_recv)

cipher_dec = Cipher(algorithms.AES(derived_key_recv), modes.GCM(iv, tag))
decryptor = cipher_dec.decryptor()
decrypted = decryptor.update(ciphertext) + decryptor.finalize()

print("Decrypted text:", decrypted.decode())
