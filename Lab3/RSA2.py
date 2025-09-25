# Simple RSA without libraries

# Example RSA keys
# Public key (n, e)
n = 3233         # n = p*q, small example primes p=61, q=53
e = 17           # public exponent

# Private key (n, d)
d = 2753         # private exponent

# --- Helper: convert text to numbers and back ---
def text_to_numbers(text):
    return [ord(c) for c in text]

def numbers_to_text(nums):
    return ''.join(chr(n) for n in nums)

# --- Encryption ---
def encrypt_rsa(plaintext, e, n):
    nums = text_to_numbers(plaintext)
    cipher_nums = [pow(m, e, n) for m in nums]
    return cipher_nums

# --- Decryption ---
def decrypt_rsa(cipher_nums, d, n):
    plain_nums = [pow(c, d, n) for c in cipher_nums]
    return numbers_to_text(plain_nums)

# --- Example usage ---
plaintext = "Asymmetric Encryption"
ciphertext = encrypt_rsa(plaintext, e, n)
print("Ciphertext (numbers):", ciphertext)

decrypted = decrypt_rsa(ciphertext, d, n)
print("Decrypted text:", decrypted)
