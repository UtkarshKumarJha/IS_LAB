#!/usr/bin/env python3
"""
Hospital Management System (Lab-style)
Roles: Patient, Doctor, Auditor

Dependencies:
    pip install pycryptodome

Design decisions (simple, exam-friendly):
- Each patient has:
    - RSA keypair (for signing): stored under data/patients/<id>/private.pem and public.pem
    - Encrypted medical records stored as <timestamp>_<filename>.enc
    - Each encrypted record has a signature file <samename>.sig which is RSA-signature of SHA512(file_plaintext)
    - A small metadata JSON 'records.json' lists records and timestamps and verification results
- AES encryption: AES-256-CBC with a key derived from a patient-supplied password using PBKDF2 (salt stored)
- Doctor decrypts if doctor knows patient's password (as required in the lab)
- Auditor can read metadata and verify signatures but cannot decrypt without password

This code focuses on readability and correctness for the lab. Not production cryptography policies (no KDF params tuning, no HSMs).
"""

import os
import json
import getpass
import base64
from pathlib import Path
from datetime import datetime

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

### --- Configuration --- ###
DATA_DIR = Path("data/patients")
PBKDF2_ITER = 200_000  # decent default for lab; more is safer but slower
AES_KEY_LEN = 32  # AES-256
AES_BLOCK = AES.block_size  # 16


### --- Utility helpers --- ###

def ensure_patient_dir(patient_id: str) -> Path:
    """Return the patient folder path, creating it if needed."""
    p = DATA_DIR / patient_id
    p.mkdir(parents=True, exist_ok=True)
    return p

def now_ts() -> str:
    """Timestamp used in filenames and metadata."""
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

def load_records_metadata(patient_dir: Path) -> dict:
    meta_path = patient_dir / "records.json"
    if meta_path.exists():
        return json.loads(meta_path.read_text())
    else:
        return {"records": []}

def save_records_metadata(patient_dir: Path, data: dict):
    meta_path = patient_dir / "records.json"
    meta_path.write_text(json.dumps(data, indent=2))


### --- RSA key management (for signatures) --- ###

def generate_rsa_keypair(patient_dir: Path, bits: int = 2048):
    """Generate RSA keypair and save private.pem and public.pem in patient_dir."""
    key = RSA.generate(bits)
    priv_path = patient_dir / "private.pem"
    pub_path = patient_dir / "public.pem"
    priv_path.write_bytes(key.export_key('PEM'))
    pub_path.write_bytes(key.publickey().export_key('PEM'))
    print(f"[+] Generated RSA keypair at {priv_path} and {pub_path}")

def load_private_key(patient_dir: Path) -> RSA.RsaKey:
    priv_path = patient_dir / "private.pem"
    if not priv_path.exists():
        raise FileNotFoundError("Private key not found; patient not registered.")
    return RSA.import_key(priv_path.read_bytes())

def load_public_key(patient_dir: Path) -> RSA.RsaKey:
    pub_path = patient_dir / "public.pem"
    if not pub_path.exists():
        raise FileNotFoundError("Public key not found; patient not registered.")
    return RSA.import_key(pub_path.read_bytes())


### --- AES encryption/decryption (password-derived key) --- ###

def derive_aes_key(password: str, salt: bytes) -> bytes:
    """Derive AES key from password and salt using PBKDF2."""
    return PBKDF2(password, salt, dkLen=AES_KEY_LEN, count=PBKDF2_ITER, hmac_hash_module=SHA512)

def pkcs7_pad(data: bytes) -> bytes:
    pad_len = AES_BLOCK - (len(data) % AES_BLOCK)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes) -> bytes:
    if len(data) == 0:
        raise ValueError("Invalid padding (empty).")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > AES_BLOCK:
        raise ValueError("Invalid padding length.")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes.")
    return data[:-pad_len]

def encrypt_file_aes(plain_path: Path, out_path: Path, password: str):
    """
    Encrypt a plaintext file with AES-CBC.
    Stored format (binary):
      [salt (16 bytes)] [iv (16 bytes)] [ciphertext...]
    """
    salt = get_random_bytes(16)
    key = derive_aes_key(password, salt)
    iv = get_random_bytes(AES_BLOCK)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = plain_path.read_bytes()
    padded = pkcs7_pad(plaintext)
    ciphertext = cipher.encrypt(padded)
    out_path.write_bytes(salt + iv + ciphertext)
    print(f"[+] Encrypted {plain_path.name} -> {out_path.name}")

def decrypt_file_aes(enc_path: Path, out_path: Path, password: str):
    """
    Decrypt the encrypted format created above.
    """
    data = enc_path.read_bytes()
    if len(data) < 16 + AES_BLOCK:
        raise ValueError("Encrypted file too short or corrupted.")
    salt = data[:16]
    iv = data[16:16+AES_BLOCK]
    ciphertext = data[16+AES_BLOCK:]
    key = derive_aes_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    plaintext = pkcs7_unpad(padded)
    out_path.write_bytes(plaintext)
    print(f"[+] Decrypted {enc_path.name} -> {out_path.name}")


### --- RSA signing and verification (of SHA512 hash) --- ###

def sign_file_rsa(file_path: Path, priv_key: RSA.RsaKey, sig_out: Path):
    """
    Compute SHA512(file) and RSA-sign it (PKCS#1 v1.5).
    Save signature as binary file.
    """
    data = file_path.read_bytes()
    h = SHA512.new(data)
    signature = pkcs1_15.new(priv_key).sign(h)
    sig_out.write_bytes(signature)
    print(f"[+] Signature saved to {sig_out.name}")

def verify_file_signature(file_path: Path, sig_path: Path, pub_key: RSA.RsaKey) -> bool:
    """
    Verify signature. Returns True if valid, False otherwise.
    """
    data = file_path.read_bytes()
    h = SHA512.new(data)
    signature = sig_path.read_bytes()
    try:
        pkcs1_15.new(pub_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


### --- High-level role actions --- ###

def patient_register(patient_id: str):
    pdir = ensure_patient_dir(patient_id)
    # Create RSA keypair if not present
    priv = pdir / "private.pem"
    pub = pdir / "public.pem"
    if priv.exists() or pub.exists():
        print("[!] Patient already registered (keys exist).")
        return
    generate_rsa_keypair(pdir)

def patient_upload_record(patient_id: str, plaintext_file: str):
    """
    Patient uploads a file: we encrypt it with AES (password-based),
    then sign the original plaintext with patient's RSA private key.
    We store encrypted file and signature, and metadata entry.
    """
    pdir = ensure_patient_dir(patient_id)
    priv = load_private_key(pdir)

    plain_path = Path(plaintext_file)
    if not plain_path.exists():
        print("[!] File does not exist.")
        return

    # Ask patient for a password used to derive AES key
    # Using getpass so password not shown on terminal
    password = getpass.getpass(prompt="Enter AES password (patient): ")

    ts = now_ts()
    out_name = f"{ts}_{plain_path.name}.enc"
    sig_name = f"{ts}_{plain_path.name}.sig"

    enc_path = pdir / out_name
    sig_path = pdir / sig_name

    # Encrypt file using AES (password-derived)
    encrypt_file_aes(plain_path, enc_path, password)

    # Sign plaintext (lab asked to sign hash of medical record)
    # We sign the plaintext, not the ciphertext, so doctor can verify after decrypt.
    sign_file_rsa(plain_path, priv, sig_path)

    # Update metadata
    meta = load_records_metadata(pdir)
    meta["records"].append({
        "timestamp": ts,
        "original_filename": plain_path.name,
        "encrypted_filename": out_name,
        "signature_filename": sig_name,
        "uploaded_at": datetime.utcnow().isoformat() + "Z",
        "verification_by_doctor": None  # doctor will fill after verifying
    })
    save_records_metadata(pdir, meta)
    print("[+] Upload completed and metadata updated.")


def patient_view_records(patient_id: str):
    """
    Patient can view metadata and also optionally view decrypted record if they provide password.
    The simpler "view old past records with timestamp" can mean showing file list + timestamps.
    """
    pdir = ensure_patient_dir(patient_id)
    meta = load_records_metadata(pdir)
    if not meta["records"]:
        print("[i] No records.")
        return
    print(f"Records for patient {patient_id}:")
    for idx, r in enumerate(meta["records"], 1):
        print(f"{idx}. {r['original_filename']} uploaded_at={r['uploaded_at']} encrypted={r['encrypted_filename']} signature={r['signature_filename']} doctor_verification={r.get('verification_by_doctor')}")

    # Optionally allow patient to decrypt a specific record (they must provide password)
    choice = input("Want to decrypt a record locally? (y/N): ").strip().lower()
    if choice == "y":
        i = int(input("Enter record number: ").strip()) - 1
        if i < 0 or i >= len(meta["records"]):
            print("[!] Invalid record number.")
            return
        enc_path = pdir / meta["records"][i]["encrypted_filename"]
        if not enc_path.exists():
            print("[!] Encrypted file missing.")
            return
        password = getpass.getpass(prompt="Enter AES password: ")
        out_path = pdir / f"decrypted_{meta['records'][i]['original_filename']}"
        try:
            decrypt_file_aes(enc_path, out_path, password)
            print(f"[+] Decrypted file written to {out_path} (open with a text editor).")
        except Exception as e:
            print(f"[!] Decryption failed: {e}")


def doctor_decrypt_and_verify(patient_id: str):
    """
    Doctor decrypts a patient's file (must know patient password),
    hashes decrypted file and stores hash, then verifies signature using patient's public key,
    and logs verification result in metadata.
    """
    pdir = ensure_patient_dir(patient_id)
    meta = load_records_metadata(pdir)
    if not meta["records"]:
        print("[i] No records for patient.")
        return

    # list records
    print("Available records:")
    for idx, r in enumerate(meta["records"], 1):
        print(f"{idx}. {r['original_filename']} (enc: {r['encrypted_filename']}) uploaded_at={r['uploaded_at']}")

    i = int(input("Enter record number to decrypt & verify: ").strip()) - 1
    if i < 0 or i >= len(meta["records"]):
        print("[!] Invalid record number.")
        return

    rec = meta["records"][i]
    enc_path = pdir / rec["encrypted_filename"]
    sig_path = pdir / rec["signature_filename"]

    if not enc_path.exists():
        print("[!] Encrypted file missing.")
        return
    if not sig_path.exists():
        print("[!] Signature file missing.")
        return

    # Doctor needs the patient's password to decrypt (lab rule)
    password = getpass.getpass(prompt="Enter patient's AES password (doctor): ")
    temp_out = pdir / f"doctor_decrypted_{rec['original_filename']}"
    try:
        decrypt_file_aes(enc_path, temp_out, password)
    except Exception as e:
        print(f"[!] Decryption failed: {e}")
        return

    # Compute SHA512 of decrypted file and save (lab asked to store SHA512 by doctor)
    data = temp_out.read_bytes()
    h = SHA512.new(data)
    hash_hex = h.hexdigest()
    # We'll store it in metadata under verification_by_doctor
    pub = load_public_key(pdir)

    # Verify signature: note signature was made on the plaintext by patient
    verified = verify_file_signature(temp_out, sig_path, pub)
    result = {
        "verified_at": datetime.utcnow().isoformat() + "Z",
        "sha512": hash_hex,
        "signature_valid": verified
    }
    rec["verification_by_doctor"] = result
    save_records_metadata(pdir, meta)

    print(f"[+] SHA512 (hex): {hash_hex}")
    print(f"[+] Signature valid: {verified}")

    # Offer to keep decrypted file or remove it
    keep = input("Keep decrypted file for doctor? (y/N): ").strip().lower()
    if keep != "y":
        try:
            temp_out.unlink()
            print("[+] Temporary decrypted file removed.")
        except Exception:
            pass


def auditor_view_and_verify(patient_id: str):
    """
    Auditor can list records + timestamps, view metadata, and verify signatures (but cannot decrypt).
    Verification is done against the decrypted content only if auditor has plaintext.
    However, the lab's requirement usually expects auditor to be able to verify signatures of old records:
    - They can verify the signature if original plaintext is available (e.g., stored somewhere in clear)
    - BUT typical lab expects auditor verifies signature stored with record (signature verifies plaintext hash)
    Here we'll allow the auditor to verify using the signature and the public key if plaintext is present.
    Since auditors cannot decrypt, we show them the available files and let them verify only if plaintext present.
    """
    pdir = ensure_patient_dir(patient_id)
    meta = load_records_metadata(pdir)
    if not meta["records"]:
        print("[i] No records.")
        return

    print("Records (auditor view):")
    for idx, r in enumerate(meta["records"], 1):
        print(f"{idx}. {r['original_filename']} uploaded={r['uploaded_at']} encrypted={r['encrypted_filename']} signature={r['signature_filename']} doctor_verification={r.get('verification_by_doctor')}")

    choice = input("Do you want to verify a signature? (y/N): ").strip().lower()
    if choice != "y":
        return

    i = int(input("Enter record number: ").strip()) - 1
    if i < 0 or i >= len(meta["records"]):
        print("[!] Invalid record number.")
        return

    rec = meta["records"][i]
    sig_path = pdir / rec["signature_filename"]
    pub = load_public_key(pdir)

    # The auditor normally cannot decrypt the encrypted file. They can verify only if plaintext is available.
    # We'll check if there's a plaintext file present (e.g., patient kept one), or if doctor left a decrypted file.
    potential_plain = pdir / rec["original_filename"]
    alt_plain = pdir / f"doctor_decrypted_{rec['original_filename']}"
    if potential_plain.exists():
        plain = potential_plain
    elif alt_plain.exists():
        plain = alt_plain
    else:
        print("[!] No plaintext available to verify (auditor cannot decrypt). If you have plaintext, place it in the patient's folder with the original filename.")
        return

    ok = verify_file_signature(plain, sig_path, pub)
    print(f"[+] Signature verification result on {plain.name}: {ok}")


### --- CLI Menu --- ###

def patient_menu():
    while True:
        print("\n--- PATIENT MENU ---")
        print("1. Register (generate RSA keypair)")
        print("2. Upload (encrypt file + sign SHA512)")
        print("3. View records (list, optionally decrypt)")
        print("0. Back")
        choice = input("Choice: ").strip()
        if choice == "1":
            pid = input("Enter patient id: ").strip()
            patient_register(pid)
        elif choice == "2":
            pid = input("Enter patient id: ").strip()
            file_path = input("Path to plaintext file (txt): ").strip()
            patient_upload_record(pid, file_path)
        elif choice == "3":
            pid = input("Enter patient id: ").strip()
            patient_view_records(pid)
        elif choice == "0":
            break
        else:
            print("Invalid choice.")

def doctor_menu():
    while True:
        print("\n--- DOCTOR MENU ---")
        print("1. Decrypt & verify a patient's record")
        print("0. Back")
        choice = input("Choice: ").strip()
        if choice == "1":
            pid = input("Enter patient id: ").strip()
            doctor_decrypt_and_verify(pid)
        elif choice == "0":
            break
        else:
            print("Invalid choice.")

def auditor_menu():
    while True:
        print("\n--- AUDITOR MENU ---")
        print("1. View records & verify signature")
        print("0. Back")
        choice = input("Choice: ").strip()
        if choice == "1":
            pid = input("Enter patient id: ").strip()
            auditor_view_and_verify(pid)
        elif choice == "0":
            break
        else:
            print("Invalid choice.")


def main_menu():
    print("=== Simple Hospital Management System (Lab) ===")
    while True:
        print("\nSelect role:")
        print("1. Patient")
        print("2. Doctor")
        print("3. Auditor")
        print("0. Exit")
        role = input("Choice: ").strip()
        if role == "1":
            patient_menu()
        elif role == "2":
            doctor_menu()
        elif role == "3":
            auditor_menu()
        elif role == "0":
            print("Bye. Try not to lose any RSA private keys.")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    main_menu()
