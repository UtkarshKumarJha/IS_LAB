from Crypto.Cipher import DES

def pkcs5_pad(s: bytes, block_size: int = 8) -> bytes:
    pad_len = block_size - (len(s) % block_size)
    return s + bytes([pad_len]) * pad_len

def pkcs5_unpad(s: bytes) -> bytes:
    pad_len = s[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Invalid padding")
    return s[:-pad_len]

if __name__ == "__main__":
    key = b"A1B2C3D4" 
    plaintext = "Confidential Data" 

    pt_bytes = plaintext.encode('utf-8')
    pt_padded = pkcs5_pad(pt_bytes, 8)

    # encrypt (ECB)
    des = DES.new(key, DES.MODE_ECB)
    ciphertext = des.encrypt(pt_padded)

    print("Ciphertext (hex):", ciphertext.hex())

    # decrypt
    des2 = DES.new(key, DES.MODE_ECB)
    decrypted_padded = des2.decrypt(ciphertext)
    decrypted = pkcs5_unpad(decrypted_padded).decode('utf-8')

    print("Decrypted plaintext:", decrypted)
