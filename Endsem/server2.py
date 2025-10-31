#!/usr/bin/env python3
"""
server.py
Payment-gateway + Paillier keyserver + RSA signing server.

Listens for JSON requests from clients (sellers) over TCP sockets.
Provides Paillier public key on request.
Accepts encrypted transactions from sellers, computes homomorphic totals,
decrypts, builds a deterministic transaction summary, signs it with RSA private key,
and returns the signed summary to client.

Usage:
    python server.py
"""

import socket
import threading
import json
import hashlib
import base64
import struct
import random
from math import gcd

# -------------------------
# Helper math primitives
# -------------------------
def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m

def is_probable_prime(n, k=8):
    # Miller-Rabin
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d//=2
        s+=1
    for _ in range(k):
        a = random.randrange(2, n-1)
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        for __ in range(s-1):
            x = pow(x, 2, n)
            if x == n-1:
                break
        else:
            return False
    return True

def generate_prime(bits=128):
    while True:
        candidate = random.getrandbits(bits) | (1 << (bits-1)) | 1
        if is_probable_prime(candidate):
            return candidate

# -------------------------
# Paillier implementation
# -------------------------
class PaillierPrivateKey:
    def __init__(self, p, q, n, lam, mu, g):
        self.p = p
        self.q = q
        self.n = n
        self.lam = lam
        self.mu = mu
        self.g = g
        self.nsq = n * n

    def decrypt(self, c):
        # c^lambda mod n^2
        u = pow(c, self.lam, self.nsq)
        L = (u - 1) // self.n
        m = (L * self.mu) % self.n
        return m

class PaillierPublicKey:
    def __init__(self, n, g):
        self.n = n
        self.g = g
        self.nsq = n * n

    def encrypt(self, m):
        # pick r in Z_n^*
        while True:
            r = random.randrange(1, self.n)
            if gcd(r, self.n) == 1:
                break
        c = (pow(self.g, m, self.nsq) * pow(r, self.n, self.nsq)) % self.nsq
        return c

def generate_paillier_keypair(bits=128):
    # Small bits for demo; increase for real usage
    p = generate_prime(bits//2)
    q = generate_prime(bits//2)
    n = p * q
    nsq = n * n
    g = n + 1  # common choice simplifies mu calculation
    lam = (p-1)*(q-1)  # not lcm for demo; lcm recommended in literature: lcm(p-1,q-1)
    # compute mu = (L(g^lambda mod n^2))^{-1} mod n
    u = pow(g, lam, nsq)
    L = (u - 1) // n
    mu = modinv(L, n)
    priv = PaillierPrivateKey(p,q,n,lam,mu,g)
    pub = PaillierPublicKey(n,g)
    return pub, priv

# -------------------------
# RSA signing (simple)
# -------------------------
def generate_rsa_keypair(bits=512):
    # small RSA keys for demo
    e = 65537
    while True:
        p = generate_prime(bits//2)
        q = generate_prime(bits//2)
        if p == q:
            continue
        phi = (p-1)*(q-1)
        if gcd(e, phi) == 1:
            break
    n = p*q
    d = modinv(e, phi)
    return (n, e), (n, d)  # public, private

def rsa_sign(private_key, message_bytes):
    n, d = private_key
    h = int.from_bytes(hashlib.sha256(message_bytes).digest(), 'big')
    signature = pow(h, d, n)
    return signature

def rsa_verify(public_key, message_bytes, signature):
    n, e = public_key
    h = int.from_bytes(hashlib.sha256(message_bytes).digest(), 'big')
    h2 = pow(signature, e, n)
    return h == h2

# -------------------------
# Networking helpers
# -------------------------
def send_json(conn, obj):
    data = json.dumps(obj, separators=(',', ':')).encode()
    # prefix length
    conn.sendall(struct.pack('>I', len(data)))
    conn.sendall(data)

def recv_json(conn):
    raw = conn.recv(4)
    if not raw:
        return None
    (length,) = struct.unpack('>I', raw)
    data = b''
    while len(data) < length:
        more = conn.recv(length - len(data))
        if not more:
            raise ConnectionError("socket closed")
        data += more
    obj = json.loads(data.decode())
    return obj

# -------------------------
# Server logic
# -------------------------
PAILLIER_BITS = 256  # demo; increase in production
RSA_BITS = 512       # demo

print("Generating keys... (this may take a second)")
paillier_pub, paillier_priv = generate_paillier_keypair(bits=PAILLIER_BITS)
rsa_pub, rsa_priv = generate_rsa_keypair(bits=RSA_BITS)
print("Keys ready.")
# We'll expose Paillier public key and RSA public key to clients.

HOST = '127.0.0.1'
PORT = 9000

def deterministic_summary_for_signing(summary):
    """
    Build a deterministic string representation (JSON with sorted keys)
    used for hashing/signing.
    """
    return json.dumps(summary, separators=(',', ':'), sort_keys=True).encode()

def process_seller_payload(payload):
    """
    payload expected fields:
      seller_name: str
      encrypted_amounts: [base64 of integers as decimal strings] or integers in decimal strings
    Returns summary dict for the seller, including totals and signature to be added later.
    """
    seller = payload['seller_name']
    enc_amounts = payload['encrypted_amounts']  # list of decimal-string ints
    # convert to int
    enc_ints = [int(x) for x in enc_amounts]
    # decrypt each amount
    dec_amounts = [paillier_priv.decrypt(c) for c in enc_ints]
    # homomorphic total: multiply ciphertexts modulo n^2
    total_cipher = 1
    for c in enc_ints:
        total_cipher = (total_cipher * (c % paillier_pub.nsq)) % paillier_pub.nsq
    # decrypt total
    total_decrypted = paillier_priv.decrypt(total_cipher)
    # sanity: recompute sum of decrypted numbers
    sum_plain = sum(dec_amounts) % paillier_pub.n
    # Build seller summary
    seller_summary = {
        'seller_name': seller,
        'individual_transactions_plain': dec_amounts,
        'individual_transactions_encrypted': [str(x) for x in enc_ints],
        'total_encrypted': str(total_cipher),
        'total_decrypted': total_decrypted,
        'sum_check_plain_mod_n': sum_plain
    }
    return seller_summary

def handle_client(conn, addr):
    try:
        req = recv_json(conn)
        if req is None:
            conn.close()
            return
        action = req.get('action')
        if action == 'get_paillier_pub':
            # send n and g and nsq as decimal strings
            resp = {
                'n': str(paillier_pub.n),
                'g': str(paillier_pub.g),
            }
            send_json(conn, {'status':'ok','paillier_pub':resp, 'rsa_pub':{'n':str(rsa_pub[0]),'e':str(rsa_pub[1])}})
            conn.close()
            return
        elif action == 'submit_transactions':
            # payload contains a list of sellers' payloads
            sellers_payloads = req.get('sellers')
            if not sellers_payloads:
                send_json(conn, {'status':'error','message':'no sellers provided'})
                conn.close()
                return
            overall_summary = []
            for payload in sellers_payloads:
                seller_summary = process_seller_payload(payload)
                overall_summary.append(seller_summary)
            # Build final transaction summary object
            transaction_summary = {
                'gateway': 'DemoPaymentGateway',
                'num_sellers': len(overall_summary),
                'sellers': overall_summary
            }
            # deterministically serialize and sign
            serialized = deterministic_summary_for_signing(transaction_summary)
            signature_int = rsa_sign(rsa_priv, serialized)
            # include signature and rsa public key for verification by client
            result = {
                'transaction_summary': transaction_summary,
                'signature': str(signature_int),
                'rsa_public': {'n': str(rsa_pub[0]), 'e': str(rsa_pub[1])}
            }
            send_json(conn, {'status':'ok', 'result': result})
            conn.close()
            return
        else:
            send_json(conn, {'status':'error','message':'unknown action'})
            conn.close()
            return
    except Exception as e:
        try:
            send_json(conn, {'status':'error','message':str(e)})
        except:
            pass
        conn.close()

def serve_forever():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(5)
    print(f"Server listening on {HOST}:{PORT}")
    while True:
        conn, addr = sock.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()

if __name__ == '__main__':
    serve_forever()
