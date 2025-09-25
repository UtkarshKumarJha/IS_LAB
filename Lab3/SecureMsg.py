from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
import os
import time


with open("test1MB.bin", "wb") as f:
    f.write(os.urandom(1024*1024))  # 1 MB

with open("test10MB.bin", "wb") as f:
    f.write(os.urandom(10*1024*1024))  # 10 MB
    
def rsa_file_encrypt(input_file, output_file, rsa_key):
    start_time = time.time()
    # Generate session AES key
    session_key = get_random_bytes(32)  # AES-256
    aes_cipher = AES.new(session_key, AES.MODE_EAX)
    
    # Read file and encrypt
    with open(input_file, "rb") as f:
        plaintext = f.read()
    ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext)
    
    # Encrypt session key with RSA
    rsa_cipher = PKCS1_OAEP.new(rsa_key.publickey())
    enc_session_key = rsa_cipher.encrypt(session_key)
    
    # Write to output
    with open(output_file, "wb") as f:
        f.write(len(enc_session_key).to_bytes(4,'big'))
        f.write(enc_session_key)
        f.write(aes_cipher.nonce)
        f.write(tag)
        f.write(ciphertext)
    return time.time() - start_time

def rsa_file_decrypt(input_file, output_file, rsa_key):
    start_time = time.time()
    with open(input_file, "rb") as f:
        key_len = int.from_bytes(f.read(4), 'big')
        enc_session_key = f.read(key_len)
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()
    
    # Decrypt session key
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    session_key = rsa_cipher.decrypt(enc_session_key)
    
    # Decrypt file
    aes_cipher = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    plaintext = aes_cipher.decrypt_and_verify(ciphertext, tag)
    
    with open(output_file, "wb") as f:
        f.write(plaintext)
    return time.time() - start_time

# --- Example usage ---
start_gen = time.time()
rsa_key = RSA.generate(2048)
key_gen_time = time.time() - start_gen

encrypt_time = rsa_file_encrypt("test1MB.bin", "rsa_enc.bin", rsa_key)
decrypt_time = rsa_file_decrypt("rsa_enc.bin", "rsa_dec.bin", rsa_key)

print(f"RSA key gen time: {key_gen_time:.2f}s")
print(f"RSA encryption time: {encrypt_time:.2f}s")
print(f"RSA decryption time: {decrypt_time:.2f}s")

def ecc_file_encrypt(input_file, output_file, public_key):
    start_time = time.time()
    session_key = os.urandom(32)  # AES-256
    with open(input_file, "rb") as f:
        plaintext = f.read()
    
    # Encrypt file with AES-GCM
    iv = os.urandom(12)
    aes_cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv))
    encryptor = aes_cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    
    # Generate ephemeral key for ECIES
    ephemeral_key = ec.generate_private_key(ec.SECP256R1())
    shared_secret = ephemeral_key.exchange(ec.ECDH(), public_key)
    # Derive AES key for encrypting session key
    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'ecc key').derive(shared_secret)
    aes_k = Cipher(algorithms.AES(derived_key), modes.ECB()).encryptor()
    
    # For demo, we'll just XOR session key with first block of derived key
    enc_session_key = bytes([a ^ b for a,b in zip(session_key, derived_key)])
    
    with open(output_file, "wb") as f:
        f.write(iv)
        f.write(tag)
        f.write(ephemeral_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        ))
        f.write(enc_session_key)
        f.write(ciphertext)
    return time.time() - start_time

def ecc_file_decrypt(input_file, output_file, private_key):
    start_time = time.time()
    with open(input_file, "rb") as f:
        iv = f.read(12)
        tag = f.read(16)
        epk_bytes = f.read(65)  # uncompressed point for SECP256R1
        enc_session_key = f.read(32)
        ciphertext = f.read()
    
    # Reconstruct ephemeral public key
    ephemeral_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), epk_bytes)
    
    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_pub)
    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'ecc key').derive(shared_secret)
    session_key = bytes([a ^ b for a,b in zip(enc_session_key, derived_key)])
    
    aes_cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv, tag))
    decryptor = aes_cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    with open(output_file, "wb") as f:
        f.write(plaintext)
    return time.time() - start_time

# --- Example usage ---
start_gen = time.time()
ecc_priv = ec.generate_private_key(ec.SECP256R1())
ecc_pub = ecc_priv.public_key()
key_gen_time = time.time() - start_gen

encrypt_time = ecc_file_encrypt("test1MB.bin", "ecc_enc.bin", ecc_pub)
decrypt_time = ecc_file_decrypt("ecc_enc.bin", "ecc_dec.bin", ecc_priv)

print(f"ECC key gen time: {key_gen_time:.2f}s")
print(f"ECC encryption time: {encrypt_time:.2f}s")
print(f"ECC decryption time: {decrypt_time:.2f}s")
