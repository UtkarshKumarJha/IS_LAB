"""
secure_enterprise_comm.py

Implementation of:
- KeyManager: RSA key generation, distribution, revocation
- Subsystem: performs RSA-protected Diffie-Hellman key exchange with other subsystem,
             derives AES-256 session key via HKDF, signs messages with RSA, encrypts
             payload with AES-GCM.
- Simple demo creating 3 systems (Finance A, HR B, Supply C), exchanging keys,
  sending messages, and printing timing and verification information.

Requires: cryptography
pip install cryptography
"""

import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.backends import default_backend
import os

# ---------------------------
# KeyManager
# ---------------------------

class KeyManager:
    """
    Generates and stores RSA key pairs for subsystems.
    Maintains a simple revocation list.
    """
    def __init__(self, rsa_bits: int = 2048):
        self.rsa_bits = rsa_bits
        self._store: Dict[str, rsa.RSAPrivateKey] = {}
        self._revoked = set()

    def register_subsystem(self, name: str) -> float:
        """Generate an RSA keypair for a subsystem and store it.
           Returns time taken (seconds) for generation."""
        start = time.perf_counter()
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.rsa_bits,
            backend=default_backend()
        )
        elapsed = time.perf_counter() - start
        self._store[name] = private_key
        return elapsed

    def get_private_key(self, name: str) -> Optional[rsa.RSAPrivateKey]:
        return None if name not in self._store else self._store[name]

    def get_public_bytes(self, name: str) -> Optional[bytes]:
        pk = self.get_private_key(name)
        if pk is None:
            return None
        pub = pk.public_key()
        return pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def get_public_key_object(self, name: str) -> Optional[rsa.RSAPublicKey]:
        pk = self.get_private_key(name)
        return None if pk is None else pk.public_key()

    def revoke(self, name: str):
        if name in self._store:
            self._revoked.add(name)

    def is_revoked(self, name: str) -> bool:
        return name in self._revoked

# ---------------------------
# Utilities for RSA encrypt/sign
# ---------------------------

def rsa_encrypt_with_public_key(pubkey: rsa.RSAPublicKey, data: bytes) -> bytes:
    return pubkey.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt_with_private_key(privkey: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    return privkey.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_sign(privkey: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return privkey.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def rsa_verify(pubkey: rsa.RSAPublicKey, signature: bytes, data: bytes) -> bool:
    try:
        pubkey.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# ---------------------------
# Subsystem (node)
# ---------------------------

@dataclass
class EncryptedMessage:
    """What gets transmitted over the network (simulated)"""
    encrypted_dh_pub_from_sender: bytes   # RSA(OAEP) encrypted sender DH public bytes
    encrypted_dh_pub_from_receiver: Optional[bytes]  # RSA encrypted response public bytes (may be None if stepwise)
    aes_nonce: bytes
    aes_ciphertext: bytes
    aes_tag: bytes
    signature: bytes  # RSA signature over the ciphertext (sender signature)

class Subsystem:
    def __init__(self, name: str, key_manager: KeyManager, dh_parameters: dh.DHParameters):
        self.name = name
        self.km = key_manager
        self.dh_params = dh_parameters
        self._rsa_priv = key_manager.get_private_key(name)
        if self._rsa_priv is None:
            raise ValueError(f"No RSA key registered for subsystem {name}")
        # ephemeral DH private key will be generated per-session
        self._last_dh_private = None
        self._last_dh_public_bytes = None

    def make_dh_ephemeral(self) -> Tuple[dh.DHPrivateKey, bytes]:
        """Generate ephemeral DH private key and return (priv, serialized_pub_bytes)"""
        priv = self.dh_params.generate_private_key()
        pub = priv.public_key()
        pub_bytes = pub.public_bytes(
            Encoding := serialization.Encoding.PEM,
            PublicFormat := serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # store for later shared secret computation
        self._last_dh_private = priv
        self._last_dh_public_bytes = pub_bytes
        return priv, pub_bytes

    def start_secure_send(self, recipient_name: str, plaintext: bytes) -> Tuple[EncryptedMessage, float]:
        """
        Initiator-side routine:
        - Generate ephemeral DH key (a_priv)
        - Pack a_pub_bytes and encrypt it with recipient RSA public key (RSA-OAEP)
        - Transmit encrypted a_pub to recipient (simulated), recipient responds with encrypted b_pub
          (for simplicity we call recipient.receive_and_respond to simulate network)
        - Use both pub values to derive symmetric AES key via HKDF
        - AES-GCM encrypt plaintext, sign ciphertext with RSA-PSS, and return assembled payload
        Returns (EncryptedMessage, total_time_seconds)
        """
        start_total = time.perf_counter()

        # check revocation
        if self.km.is_revoked(recipient_name):
            raise PermissionError("Recipient key is revoked; aborting send.")

        # 1) make ephemeral DH and encrypt its public bytes to recipient using recipient's RSA pubkey
        a_priv, a_pub_bytes = self.make_dh_ephemeral()
        recipient_pubkey = self.km.get_public_key_object(recipient_name)
        if recipient_pubkey is None:
            raise ValueError("Recipient unknown")

        enc_a_pub = rsa_encrypt_with_public_key(recipient_pubkey, a_pub_bytes)

        # simulate sending enc_a_pub to recipient and receiving enc_b_pub in response:
        recipient = network_registry.get(recipient_name)
        if recipient is None:
            raise ValueError("Recipient subsystem not available on network registry")

        # recipient receives enc_a_pub and replies with enc_b_pub (RSA-encrypted b_pub)
        enc_b_pub = recipient.receive_and_respond(self.name, enc_a_pub)

        # 2) decrypt recipient's encrypted b_pub (recipient encrypted with sender's public key)
        # but the sender does not need to decrypt enc_b_pub: the recipient encrypts its b_pub with sender's RSA pubkey,
        # so sender must decrypt with its own private key to get b_pub
        my_privkey = self._rsa_priv
        b_pub_bytes = rsa_decrypt_with_private_key(my_privkey, enc_b_pub)

        # reconstruct peer public key and compute shared secret
        peer_pub = serialization.load_pem_public_key(b_pub_bytes, backend=default_backend())
        shared = a_priv.exchange(peer_pub)  # raw shared bytes

        # derive AES key from shared secret
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"securecorp session key"
        ).derive(shared)

        # 3) encrypt plaintext with AES-GCM
        nonce = os.urandom(12)
        aes_cipher = Cipher(algorithms.AES(derived_key), modes.GCM(nonce), backend=default_backend())
        encryptor = aes_cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag

        # 4) sign ciphertext (and tag/nonce) to provide sender authenticity
        to_sign = nonce + tag + ciphertext
        signature = rsa_sign(my_privkey, to_sign)

        total_time = time.perf_counter() - start_total

        return EncryptedMessage(
            encrypted_dh_pub_from_sender=enc_a_pub,
            encrypted_dh_pub_from_receiver=enc_b_pub,
            aes_nonce=nonce,
            aes_ciphertext=ciphertext,
            aes_tag=tag,
            signature=signature
        ), total_time

    def receive_and_respond(self, sender_name: str, enc_a_pub_bytes: bytes) -> bytes:
        """
        Recipient-side handler:
        - Decrypt enc_a_pub_bytes with own RSA private key to get a_pub_bytes
        - Generate ephemeral DH key pair (b_priv, b_pub_bytes)
        - Compute shared = b_priv.exchange(a_pub)
        - Encrypt b_pub_bytes with sender's RSA public key and return
        Note: actual message payload will be sent after this DH handshake by the sender.
        """
        # check revoked
        if self.km.is_revoked(sender_name):
            raise PermissionError("Sender key revoked; refusing to respond.")

        my_priv = self._rsa_priv
        a_pub_bytes = rsa_decrypt_with_private_key(my_priv, enc_a_pub_bytes)
        a_pub = serialization.load_pem_public_key(a_pub_bytes, backend=default_backend())

        # generate own ephemeral and compute shared for internal use (we won't encrypt message here)
        b_priv, b_pub_bytes = self.make_dh_ephemeral()
        shared = b_priv.exchange(a_pub)

        # store derived key in ephemeral session store keyed by sender to allow decrypt when message arrives
        # we'll store derived_key in a short-lived dict (simulation)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"securecorp session key"
        ).derive(shared)
        ephemeral_session_store[(self.name, sender_name)] = derived_key

        # encrypt b_pub_bytes with sender's RSA public key so sender can decrypt and compute same shared
        sender_pubkey = self.km.get_public_key_object(sender_name)
        if sender_pubkey is None:
            raise ValueError("Unknown sender public key")
        enc_b_pub = rsa_encrypt_with_public_key(sender_pubkey, b_pub_bytes)
        return enc_b_pub

    def receive_message_and_decrypt(self, sender_name: str, msg: EncryptedMessage) -> Tuple[bytes, float]:
        """
        Called by recipient after it receives EncryptedMessage from sender.
        - Verify signature (sender's RSA public key)
        - Use the derived key from ephemeral_session_store to decrypt AES-GCM
        Returns: (plaintext bytes, time_taken)
        """
        start = time.perf_counter()
        if self.km.is_revoked(sender_name):
            raise PermissionError("Sender revoked")

        # 1) verify signature using sender's public key
        sender_pub = self.km.get_public_key_object(sender_name)
        if sender_pub is None:
            raise ValueError("Unknown sender")
        to_verify = msg.aes_nonce + msg.aes_tag + msg.aes_ciphertext
        if not rsa_verify(sender_pub, msg.signature, to_verify):
            raise ValueError("Signature verification failed")

        # 2) retrieve ephemeral derived key from session store
        derived_key = ephemeral_session_store.get((self.name, sender_name))
        if derived_key is None:
            raise ValueError("No ephemeral session key found for this sender->recipient pair. Did you complete handshake?")

        # 3) decrypt AES-GCM
        aes_cipher = Cipher(algorithms.AES(derived_key), modes.GCM(msg.aes_nonce, msg.aes_tag), backend=default_backend())
        decryptor = aes_cipher.decryptor()
        plaintext = decryptor.update(msg.aes_ciphertext) + decryptor.finalize()

        elapsed = time.perf_counter() - start
        return plaintext, elapsed

# ---------------------------
# Simulated network/global registries
# ---------------------------

network_registry: Dict[str, Subsystem] = {}  # maps subsystem name -> Subsystem instance
ephemeral_session_store: Dict[Tuple[str,str], bytes] = {}  # (recipient, sender) -> derived_key

# ---------------------------
# Demo / Example usage
# ---------------------------

def demo():
    print("=== SecureCorp Secure Communication Demo ===")
    km = KeyManager(rsa_bits=2048)

    # Register subsystems and measure RSA key generation time
    subsystems = ["FinanceA", "HRB", "SupplyC"]
    gen_times = {}
    for s in subsystems:
        t = km.register_subsystem(s)
        gen_times[s] = t
        print(f"Registered {s}, RSA key gen time: {t:.3f}s")

    # Create shared DH parameters once for the enterprise (scalable)
    print("\nGenerating enterprise DH parameters (2048-bit) ...")
    t0 = time.perf_counter()
    dh_parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    t1 = time.perf_counter()
    print(f"DH parameters generated in {t1-t0:.3f}s")

    # Instantiate subsystem objects and register them into simulated network
    for s in subsystems:
        node = Subsystem(s, km, dh_parameters)
        network_registry[s] = node

    # Example: FinanceA -> HRB secure message
    sender = network_registry["FinanceA"]
    receiver = network_registry["HRB"]
    message = b"Confidential payroll report: total=USD 1,234,567.89"

    print("\n=== FinanceA -> HRB Secure Exchange ===")
    enc_msg, total_handshake_and_encrypt_time = sender.start_secure_send("HRB", message)
    print(f"Sender: handshake + encrypt elapsed {total_handshake_and_encrypt_time:.4f}s")

    # On HRB side, decrypt and verify
    plaintext, decrypt_time = receiver.receive_message_and_decrypt("FinanceA", enc_msg)
    print(f"Receiver: verified and decrypted in {decrypt_time:.6f}s")
    print("Recovered message:", plaintext.decode())

    # Example: HRB -> SupplyC
    sender2 = network_registry["HRB"]
    receiver2 = network_registry["SupplyC"]
    message2 = b"Purchase Order #12345: Item=Widgets, Qty=1000, Value=USD 50,000"
    print("\n=== HRB -> SupplyC Secure Exchange ===")
    enc_msg2, t_sent = sender2.start_secure_send("SupplyC", message2)
    print(f"Sender2: handshake + encrypt elapsed {t_sent:.4f}s")
    pt2, t_dec2 = receiver2.receive_message_and_decrypt("HRB", enc_msg2)
    print(f"Receiver2: verified and decrypted in {t_dec2:.6f}s")
    print("Recovered message:", pt2.decode())

    # Revoke HRB and attempt to send to HRB should fail
    print("\n=== Demonstrate revocation ===")
    km.revoke("HRB")
    print("HRB revoked in KeyManager.")
    try:
        sender.start_secure_send("HRB", b"This should fail")
    except PermissionError as e:
        print("Expected failure after revocation:", str(e))

    print("\n=== Summary of timings ===")
    for s, t in gen_times.items():
        print(f"{s} RSA key gen time: {t:.3f}s")
    print(f"DH parameter generation time: {t1-t0:.3f}s")
    print("Note: per-exchange times printed inline above.")

if __name__ == "__main__":
    demo()
