import numpy as np
import string

def preprocess_text(text):
    text = text.upper()
    text = ''.join(ch for ch in text if ch.isalpha())
    if len(text)%2 != 0:
        text += 'X'
    return text

def mod_inverse(a,m):
    a = a%m
    for x in range(1,m):
        if(a*x)%m == 1:
            return x
    raise ValueError("No modular inverse exists")

def hill_encrypt(plaintext,K):
    letters = string.ascii_uppercase
    letter_to_num = {letters[i]:i for i in range(26)}
    num_to_letter = {i:letters[i] for i in range(26)}
    
    plain = preprocess_text(plaintext)
    
    cipher = ''
    for i in range(0,len(plain),2):
        pair = plain[i:i+2]
        vec = np.array([[letter_to_num[pair[0]]],[letter_to_num[pair[1]]]])
        enc = np.dot(K,vec)%26
        cipher += num_to_letter[enc[0][0]] + num_to_letter[enc[1][0]]
    return plain,cipher

def hill_decrypt(cipher,K):
    letter = string.ascii_uppercase
    letter_to_num = {letter[i]:i for i in range(26)}
    num_to_letter = {i:letter[i] for i in range(26)}
    det = int(np.round(np.linalg.det(K)))
    det_inv = mod_inverse(det,26)
    adj = np.array([[K[1][1],-K[0][1]],[-K[1][0],K[0][0]]])
    K_inv = (det_inv*adj)%26
    
    plain = ''
    for i in range(0,len(cipher),2):
        pair = cipher[i:i+2]
        vec = np.array([[letter_to_num[pair[0]]],[letter_to_num[pair[1]]]])
        dec = np.dot(K_inv,vec)%26
        plain += num_to_letter[dec[0][0]] + num_to_letter[dec[1][0]]
    return plain,cipher

if __name__ == "__main__":
    K = np.array([[3,3],[2,7]])
    msg = input("Enter plaintext:")
    plain,cipher = hill_encrypt(msg,K)
    print("Plaintext:",plain)
    print("Ciphertext:",cipher)