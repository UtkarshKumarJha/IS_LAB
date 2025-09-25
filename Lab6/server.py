import socket, hashlib

def verify_signature(msg, sig, params, pubkey):
    p, g, y = params
    r, s = sig
    H = int(hashlib.sha256(msg.encode()).hexdigest(), 16) % p
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, H, p)
    return v1 == v2

server = socket.socket()
server.bind(("localhost", 9999))
server.listen(1)

print("Server waiting...")
conn, _ = server.accept()
data = conn.recv(4096).decode().split("||")
msg, r, s, p, g, y = data[0], int(data[1]), int(data[2]), int(data[3]), int(data[4]), int(data[5])
params = (p, g, y)

if verify_signature(msg, (r, s), params, y):
    print("✅ Signature Verified:", msg)
else:
    print("❌ Signature Failed!")

conn.close()

import socket, hashlib, random

def elgamal_sign(msg, priv, p, g, y):
    H = int(hashlib.sha256(msg.encode()).hexdigest(), 16) % p
    k = random.randint(2, p-2)
    r = pow(g, k, p)
    s = ((H - priv * r) * pow(k, -1, p-1)) % (p-1)
    return (r, s)

p, g, priv = 30803, 2, 1234
y = pow(g, priv, p)

msg = "Finance Report"
r, s = elgamal_sign(msg, priv, p, g, y)

client = socket.socket()
client.connect(("localhost", 9999))
client.send(f"{msg}||{r}||{s}||{p}||{g}||{y}".encode())
client.close()
