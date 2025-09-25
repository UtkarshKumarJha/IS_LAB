import random
import hashlib

def schnorr_keygen(p, q, g):
    x = random.randint(1, q-1)   # private key
    y = pow(g, x, p)             # public key
    return (p, q, g, y), x

def schnorr_sign(message, priv, params):
    p, q, g, y = params
    k = random.randint(1, q-1)
    r = pow(g, k, p)
    e = int(hashlib.sha256((message + str(r)).encode()).hexdigest(), 16) % q
    s = (k + priv * e) % q
    return (r, s)

def schnorr_verify(message, sig, params):
    p, q, g, y = params
    r, s = sig
    e = int(hashlib.sha256((message + str(r)).encode()).hexdigest(), 16) % q
    v = (pow(g, s, p) * pow(y, -e, p)) % p
    return v == r

if __name__ == "__main__":
    p, q, g = 30803, 15401, 2
    pub, priv = schnorr_keygen(p, q, g)
    msg = "Top Secret File"
    
    sig = schnorr_sign(msg, priv, pub)
    print("🔏 Schnorr Signature:", sig)
    print("✅ Verified:", schnorr_verify(msg, sig, pub))
