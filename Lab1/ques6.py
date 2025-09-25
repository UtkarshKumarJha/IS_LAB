# affine_bruteforce.py
import string

CIPHER = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
ALPHA = string.ascii_uppercase
COPRIME = [1,3,5,7,9,11,15,17,19,21,23,25]  # valid 'a' values mod 26

def modinv(a, m=26):
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def affine_encrypt_letter(x, a, b):
    # x is plaintext index 0..25; returns ciphertext index
    return (a * x + b) % 26

def affine_decrypt_text(ciphertext, a_inv, b):
    plain = []
    for ch in ciphertext:
        if ch in ALPHA:
            y = ALPHA.index(ch)
            x = (a_inv * (y - b)) % 26
            plain.append(ALPHA[x])
        else:
            plain.append(ch)
    return "".join(plain)

def brute_force_with_crib(cipher, crib_plain="AB", crib_cipher="GL"):
    solutions = []
    for a in COPRIME:
        a_inv = modinv(a)
        if a_inv is None:
            continue
        for b in range(26):
            # Check crib: encrypt 'A'(0) and 'B'(1) with (a,b) must give 'G' and 'L'
            c0 = affine_encrypt_letter(0, a, b)   # should match 'G' -> index 6
            c1 = affine_encrypt_letter(1, a, b)   # should match 'L' -> index 11
            if c0 == ALPHA.index(crib_cipher[0]) and c1 == ALPHA.index(crib_cipher[1]):
                # Candidate key found; decrypt whole message
                plaintext = affine_decrypt_text(cipher, a_inv, b)
                solutions.append(((a, b), plaintext))
    return solutions

if __name__ == "__main__":
    sols = brute_force_with_crib(CIPHER, "AB", "GL")
    if not sols:
        print("No key found matching the crib.")
    else:
        for (a,b), pt in sols:
            print(f"Found key: a={a}, b={b}")
            print("Decrypted plaintext:")
            print(pt)
