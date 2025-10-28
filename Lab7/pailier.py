import random
import math

def lcm(a, b):
    return abs(a*b) // math.gcd(a, b)

def L(u, n):
    return (u - 1) // n

def generate_keys(p, q):
    n = p * q
    lam = lcm(p-1, q-1)
    n2 = n * n

    g = n + 1  # Standard choice simplifies computation
    # μ = ( L(g^λ mod n^2) )^(-1) mod n
    x = pow(g, lam, n2)
    mu = pow(L(x, n), -1, n)

    return (n, g), (lam, mu)

def encrypt(m, pubkey):
    n, g = pubkey
    n2 = n * n
    r = random.randint(1, n-1)
    return (pow(g, m, n2) * pow(r, n, n2)) % n2

def decrypt(c, pubkey, privkey):
    n, g = pubkey
    lam, mu = privkey
    n2 = n * n
    x = pow(c, lam, n2)
    return (L(x, n) * mu) % n

# ------------------------------
# DEMO
# ------------------------------

p = 47
q = 71

public_key, private_key = generate_keys(p, q)

m1 = 15
m2 = 25

print("Original:", m1, m2)

c1 = encrypt(m1, public_key)
c2 = encrypt(m2, public_key)

print("Encrypted m1:", c1)
print("Encrypted m2:", c2)

# Homomorphic addition: E(m1+m2) = E(m1) * E(m2) mod n^2
n = public_key[0]
add_encrypted = (c1 * c2) % (n*n)

print("Encrypted Addition Result:", add_encrypted)

dec_result = decrypt(add_encrypted, public_key, private_key)

print("Decrypted Sum:", dec_result)
print("Expected Sum:", m1 + m2)
