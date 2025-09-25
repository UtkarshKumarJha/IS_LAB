import hashlib, random

def dsa_keygen(p, q, g):
    x = random.randint(1, q-1)    # private key
    y = pow(g, x, p)              # public key
    return (p, q, g, y), x

def dsa_sign(message, priv, params):
    p, q, g, y = params
    H = int(hashlib.sha256(message.encode()).hexdigest(), 16) % q
    while True:
        k = random.randint(1, q-1)
        if gcd(k, q) == 1:
            break
    r = pow(g, k, p) % q
    s = (modinv(k, q) * (H + priv * r)) % q
    return (r, s)

def dsa_verify(message, sig, params):
    p, q, g, y = params
    r, s = sig
    H = int(hashlib.sha256(message.encode()).hexdigest(), 16) % q
    w = modinv(s, q)
    u1 = (H * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    return v == r

def modinv(a, m): return pow(a, -1, m)
def gcd(a, b): return gcd(b, a % b) if b else a

if __name__ == "__main__":
    p, q, g = 30803, 15401, 2
    pub, priv = dsa_keygen(p, q, g)
    msg = "Employee Contracts"
    
    sig = dsa_sign(msg, priv, pub)
    print("🔏 DSA Signature:", sig)
    print("✅ Verified:", dsa_verify(msg, sig, pub))
