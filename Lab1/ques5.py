import string

def caesar_decrypt(ciphertext, shift):
    letters = string.ascii_uppercase
    result = ""
    for ch in ciphertext:
        if ch in letters:
            idx = (letters.index(ch) + shift) % 26
            result += letters[idx]
        else:
            result += ch
    return result

cipher1 = "CIW"
plain1 = "YES"

# compute shift from first example
letters = string.ascii_uppercase
shift = (letters.index(plain1[0]) - letters.index(cipher1[0])) % 26
print("Recovered shift:", shift)

# decrypt the second ciphertext
cipher2 = "XVIEWYWI"
plaintext2 = caesar_decrypt(cipher2, shift)
print("Decrypted second ciphertext:", plaintext2)
