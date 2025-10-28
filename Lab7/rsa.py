import math
import random

def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def mod_inverse(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception("Modular inverse does not exist")
    return x % m

def generate_keys(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose e
    e = 65537  # Standard choice (fast and secure)
    
    # Compute d
    d = mod_inverse(e, phi)

    return (e, n), (d, n)

def encrypt(m, pubkey):
    e, n = pubkey
    return pow(m, e, n)

def decrypt(c, privkey):
    d, n = privkey
    return pow(c, d, n)

# ------------------------------
# DEMO
# ------------------------------

# Use decent primes (not kiddie primes)
p = 61
q = 53

public_key, private_key = generate_keys(p, q)

m1 = 7
m2 = 3

print("Original:", m1, m2)

c1 = encrypt(m1, public_key)
c2 = encrypt(m2, public_key)

print("Encrypted m1:", c1)
print("Encrypted m2:", c2)

# Homomorphic multiplication: E(a*b) = E(a) * E(b) mod n
_, n = public_key
mul_encrypted = (c1 * c2) % n

print("Encrypted Multiplication Result:", mul_encrypted)

dec_result = decrypt(mul_encrypted, private_key)

print("Decrypted Product:", dec_result)
print("Expected Product:", m1 * m2)
