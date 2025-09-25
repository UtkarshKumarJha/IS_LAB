# aes_lib.py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def hexkey_to_bytes(hexkey: str) -> bytes:
    # Accepts the hex string provided
    return bytes.fromhex(hexkey)

def aes_encrypt_ecb(plaintext: bytes, key_bytes: bytes) -> bytes:
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, AES.block_size))

def aes_decrypt_ecb(ciphertext: bytes, key_bytes: bytes) -> bytes:
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

if __name__ == "__main__":
    hex_key = "0123456789ABCDEF0123456789ABCDEF"
    key = hexkey_to_bytes(hex_key)

    message = "Sensitive Information"
    pt = message.encode("utf-8")

    ct = aes_encrypt_ecb(pt, key)
    print("Ciphertext (hex):", ct.hex().upper())

    recovered = aes_decrypt_ecb(ct, key)
    print("Decrypted plaintext:", recovered.decode("utf-8"))
