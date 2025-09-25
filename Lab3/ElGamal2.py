# --- Small prime for demo ---
p_num = input("Enter p: ")
p = int(p_num)  # prime number
g = 2          # generator
x = 127        # private key
h = pow(g, x, p)  # public key

print(f"Public key: (p={p}, g={g}, h={h})")
print(f"Private key: x={x}")

# --- Message as number ---
msg = "Confidential Data"
m = int.from_bytes(msg.encode(), byteorder='big')
print("Message as integer:", m)

# --- Encryption ---
y = 88  # ephemeral key (random)
c1 = pow(g, y, p)
c2 = (m * pow(h, y, p)) % p
print("Ciphertext:", (c1, c2))

# --- Decryption ---
s = pow(c1, x, p)
# Compute modular inverse of s modulo p
def modinv(a, m):
    # Extended Euclidean Algorithm
    g, x1, y1 = m, 0, 1
    a0, m0 = a, m
    x0, y0 = 1, 0
    while m != 0:
        q, a, m = a // m, m, a % m
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return x0 % m0

m_dec = (c2 * modinv(s, p)) % p
plaintext = m_dec.to_bytes((m_dec.bit_length()+7)//8, byteorder='big').decode()
print("Decrypted text:", plaintext)
