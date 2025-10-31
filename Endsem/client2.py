#!/usr/bin/env python3
"""
client.py
Simulates multiple sellers, each creating multiple transactions.
Client requests Paillier public key from server, encrypts transaction amounts,
sends encrypted payloads to server, receives signed transaction summary,
verifies RSA signature, and prints everything.

Usage:
    python client.py
"""

import socket
import json
import struct
import hashlib
import random
import sys
from math import gcd

HOST = '127.0.0.1'
PORT = 9000

def send_json(conn, obj):
    data = json.dumps(obj, separators=(',', ':')).encode()
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
    return json.loads(data.decode())

# -------------------------
# Paillier public operations (client-side)
# -------------------------
class PaillierPublicKey:
    def __init__(self, n, g):
        self.n = n
        self.g = g
        self.nsq = n * n

    def encrypt(self, m):
        # choose random r in Z_n^*
        while True:
            r = random.randrange(1, self.n)
            if gcd(r, self.n) == 1:
                break
        c = (pow(self.g, m, self.nsq) * pow(r, self.n, self.nsq)) % self.nsq
        return c

# -------------------------
# RSA verify (client-side)
# -------------------------
def rsa_verify_pub(public_key, message_bytes, signature_int):
    n = public_key['n']
    e = public_key['e']
    n = int(n); e = int(e)
    h = int.from_bytes(hashlib.sha256(message_bytes).digest(), 'big')
    h2 = pow(signature_int, e, n)
    return h == h2

def get_paillier_pub_from_server():
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((HOST, PORT))
    send_json(conn, {'action':'get_paillier_pub'})
    resp = recv_json(conn)
    conn.close()
    if resp['status'] != 'ok':
        raise RuntimeError("failed to get key")
    pub = resp['paillier_pub']
    rsa_pub = resp['rsa_pub']
    return PaillierPublicKey(int(pub['n']), int(pub['g'])), {'n':int(rsa_pub['n']),'e':int(rsa_pub['e'])}

def submit_transactions_to_server(sellers_payloads):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((HOST, PORT))
    send_json(conn, {'action':'submit_transactions', 'sellers': sellers_payloads})
    resp = recv_json(conn)
    conn.close()
    return resp

def deterministic_summary_for_signing(summary):
    return json.dumps(summary, separators=(',', ':'), sort_keys=True).encode()

def pretty_print_summary(result):
    print("\n===== TRANSACTION SUMMARY (Server-signed) =====")
    ts = result['transaction_summary']
    print(f"Gateway: {ts.get('gateway')}")
    print(f"Number of sellers: {ts.get('num_sellers')}")
    print()
    for s in ts['sellers']:
        print(f"--- Seller: {s['seller_name']} ---")
        print("Individual transaction amounts (decrypted / plain):")
        for amt in s['individual_transactions_plain']:
            print("  ", amt)
        print("Individual encrypted amounts (big decimals):")
        for enc in s['individual_transactions_encrypted']:
            print("  ", enc[:80] + ('...' if len(enc)>80 else ''))
        print("Total encrypted:", s['total_encrypted'][:120] + ('...' if len(s['total_encrypted'])>120 else ''))
        print("Total decrypted:", s['total_decrypted'])
        print("Sum check (mod n):", s['sum_check_plain_mod_n'])
        print()
    print("Signature (decimal):", result['signature'][:140] + ('...' if len(result['signature'])>140 else ''))
    print("RSA public key returned (n,e):", result['rsa_public']['n'][:90] + '...', result['rsa_public']['e'])
    print("==============================================\n")

if __name__ == '__main__':
    # 1) get Paillier public key
    print("Fetching Paillier public key from server...")
    paillier_pub, server_rsa_pub = get_paillier_pub_from_server()
    print("Received Paillier n with", paillier_pub.n.bit_length(), "bits (demo).")

    # 2) Simulate multiple sellers
    # You asked: at least 2 sellers and each seller >=2 transactions.
    # We'll simulate two sellers, each with 3 transactions.
    sellers = [
        {'seller_name': 'Seller_A', 'plain_amounts': [120, 230, 50]},
        {'seller_name': 'Seller_B', 'plain_amounts': [75, 125, 300]}
    ]

    # Encrypt each amount using Paillier public key and build payloads
    sellers_payloads = []
    for s in sellers:
        encs = []
        for m in s['plain_amounts']:
            c = paillier_pub.encrypt(m)
            encs.append(str(c))
        sellers_payloads.append({'seller_name': s['seller_name'], 'encrypted_amounts': encs})

    # 3) submit to server
    print("Submitting encrypted transaction payloads to server...")
    response = submit_transactions_to_server(sellers_payloads)
    if response['status'] != 'ok':
        print("Server error:", response.get('message'))
        sys.exit(1)
    res = response['result']
    # 4) verify signature
    signed_summary = res['transaction_summary']
    signature_int = int(res['signature'])
    rsa_public = res['rsa_public']
    serialized = deterministic_summary_for_signing(signed_summary)
    ok = rsa_verify_pub(rsa_public, serialized, signature_int)

    # 5) print full output and verification result
    pretty_print_summary(res)
    print("Digital Signature Verification result:", "VALID" if ok else "INVALID")
    print("\nDone.")
