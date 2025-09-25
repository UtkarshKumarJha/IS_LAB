import random
import time

# Large prime (for demo, use a small prime; in real life use 2048-bit primes!)
p = 23   # prime modulus
g = 5    # primitive root modulo p

def generate_keys(p, g):
    start_time = time.time()
    private_key = random.randint(2, p-2)
    public_key = pow(g, private_key, p)
    key_gen_time = time.time() - start_time
    return private_key, public_key, key_gen_time

def compute_shared_secret(public_other, private_self, p):
    start_time = time.time()
    shared_secret = pow(public_other, private_self, p)
    exchange_time = time.time() - start_time
    return shared_secret, exchange_time

# --- Simulation of two peers ---
# Peer A
a_priv, a_pub, a_gen = generate_keys(p, g)
# Peer B
b_priv, b_pub, b_gen = generate_keys(p, g)

# Key exchange
a_secret, a_time = compute_shared_secret(b_pub, a_priv, p)
b_secret, b_time = compute_shared_secret(a_pub, b_priv, p)

print("Prime (p):", p)
print("Generator (g):", g)
print("Peer A public key:", a_pub)
print("Peer B public key:", b_pub)
print("Shared secret (A):", a_secret)
print("Shared secret (B):", b_secret)
print("Keys match?", a_secret == b_secret)

print(f"Peer A key generation time: {a_gen:.6f} sec")
print(f"Peer B key generation time: {b_gen:.6f} sec")
print(f"Peer A key exchange time: {a_time:.6f} sec")
print(f"Peer B key exchange time: {b_time:.6f} sec")
