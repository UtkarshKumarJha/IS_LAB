from Crypto.Random import random
from Crypto.Util.number import getPrime, inverse

# --- Key generation ---
bits = 256  # small for demo; real security needs 2048+
p = getPrime(bits)
g = 2
x = random.randint(1, p-2)   # private key
h = pow(g, x, p)             # public key

print(f"Public key: (p={p}, g={g}, h={h})")
print(f"Private key: x={x}")

# --- Message as number ---
msg = "Confidential Data"
m = int.from_bytes(msg.encode(), byteorder='big')

# --- Encryption ---
y = random.randint(1, p-2)       # ephemeral key
c1 = pow(g, y, p)
c2 = (m * pow(h, y, p)) % p
print("Ciphertext:", (c1, c2))

# --- Decryption ---
s = pow(c1, x, p)
m_dec = (c2 * inverse(s, p)) % p
plaintext = m_dec.to_bytes((m_dec.bit_length()+7)//8, byteorder='big').decode()
print("Decrypted text:", plaintext)
