import socket
import hashlib
import random
import math

def elgamal_sign(msg, priv, p, g, y):
    H = int(hashlib.sha256(msg.encode()).hexdigest(), 16) % p
    while True:
        k = random.randint(2, p-2)
        if math.gcd(k, p-1) == 1:  # ensure k invertible mod (p-1)
            break
    r = pow(g, k, p)
    k_inv = pow(k, -1, p-1)
    s = ((H - priv * r) * k_inv) % (p-1)
    return (r, s)

# Parameters
p, g, priv = 30803, 2, 1234
y = pow(g, priv, p)  # public key

msg = "Finance Report"
r, s = elgamal_sign(msg, priv, p, g, y)

# Send to server
client = socket.socket()
client.connect(("localhost", 9999))
client.send(f"{msg}||{r}||{s}||{p}||{g}||{y}".encode())
client.close()

print("📤 Message + Signature sent to server.")
