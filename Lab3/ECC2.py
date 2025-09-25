# Toy ECC over small finite field
# Curve: y^2 = x^3 + ax + b mod p
p = 97
a = 2
b = 3

# Base point
G = (3, 6)

def inverse_mod(k, p):
    return pow(k, p-2, p)

def point_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    if P == Q:
        # point doubling
        s = (3*P[0]**2 + a) * inverse_mod(2*P[1], p) % p
    else:
        s = (Q[1]-P[1]) * inverse_mod(Q[0]-P[0], p) % p
    x_r = (s**2 - P[0] - Q[0]) % p
    y_r = (s*(P[0]-x_r) - P[1]) % p
    return (x_r, y_r)

def scalar_mult(k, P):
    R = None
    for bit in bin(k)[2:]:
        R = point_add(R, R)
        if bit == '1':
            R = point_add(R, P)
    return R

# --- Key generation ---
d = 20  # private key
Q = scalar_mult(d, G)  # public key
print("Private key:", d)
print("Public key:", Q)

# --- Encrypt message as a number ---
m = 45  # toy "message"
k = 15  # ephemeral key
C1 = scalar_mult(k, G)
S = scalar_mult(k, Q)
C2 = (m * S[0]) % p
print("Ciphertext:", (C1, C2))

# --- Decrypt ---
S_dec = scalar_mult(d, C1)
m_dec = (C2 * inverse_mod(S_dec[0], p)) % p
print("Decrypted message:", m_dec)
