import random
import hashlib

# Modular inverse
def modinv(a, m):
    return pow(a, -1, m)

# ElGamal Signature
def elgamal_keygen(p, g):
    x = random.randint(1, p-2)  # private key
    y = pow(g, x, p)           # public key
    return (p, g, y), x

def elgamal_sign(message, priv, params):
    p, g, y = params
    H = int(hashlib.sha256(message.encode()).hexdigest(), 16) % p
    while True:
        k = random.randint(1, p-2)
        if gcd(k, p-1) == 1:
            break
    r = pow(g, k, p)
    s = ((H - priv * r) * modinv(k, p-1)) % (p-1)
    return (r, s)

def elgamal_verify(message, sig, params):
    p, g, y = params
    r, s = sig
    H = int(hashlib.sha256(message.encode()).hexdigest(), 16) % p
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, H, p)
    return v1 == v2

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

if __name__ == "__main__":
    p, g = 30803, 2
    pub, priv = elgamal_keygen(p, g)
    msg = "Confidential Data"
    
    sig = elgamal_sign(msg, priv, pub)
    print("🔏 Signature:", sig)
    print("✅ Verified:", elgamal_verify(msg, sig, pub))
