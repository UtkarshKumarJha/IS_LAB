import socket
import hashlib

HOST = "127.0.0.1"  # localhost
PORT = 65432        # arbitrary port

def compute_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"[SERVER] Listening on {HOST}:{PORT}...")

    conn, addr = s.accept()
    with conn:
        print(f"[SERVER] Connected by {addr}")

        data = conn.recv(4096)
        if not data:
            print("[SERVER] No data received.")
        else:
            print(f"[SERVER] Received data: {data.decode(errors='ignore')}")
            hash_value = compute_hash(data)
            print(f"[SERVER] Computed hash: {hash_value}")

            # Send the hash back to client
            conn.sendall(hash_value.encode())
            print("[SERVER] Hash sent back to client.")
