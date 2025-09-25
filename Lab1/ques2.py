def gen_key(text,key):
    key = key.upper()
    key = list(key)
    if(len(text)==len(key)):
        return key
    else:
        for i in range(len(text)-len(key)):
            key.append(key[i%len(key)])
    return "".join(key)

def vigenere_encrypt(text,key):
    key = gen_key(text,key)
    cipher = []
    text = text.upper()
    for i in range(len(text)):
        res = (ord(text[i])-ord('A')+ ord(key[i])-ord('A'))%26
        cipher.append(chr(res+ord('A')))
    return "".join(cipher)

def vigenere_decrypt(cipher,key):
    key = gen_key(cipher,key)
    plain = []
    cipher = cipher.upper()
    for i in range(len(cipher)):
        res = (ord(cipher[i])-ord('A')- ord(key[i])-ord('A'))%26
        plain.append(chr(res+ord('A')))
    return "".join(plain)

def autokey_encrypt(text, key):
    text = text.upper()
    key = key.upper()
    # Extend key with plaintext
    key = (key + text)[:len(text)]
    result = ""
    for i in range(len(text)):
        if text[i].isalpha():
            res = (ord(text[i]) - ord('A') + ord(key[i]) - ord('A')) % 26
            result += chr(res + ord('A'))
        else:
            result += text[i]
    return result

def autokey_decrypt(cipher, key):
    cipher = cipher.upper()
    key = key.upper()
    result = ""
    for i in range(len(cipher)):
        if cipher[i].isalpha():
            res = (ord(cipher[i]) - ord('A') - (ord(key[i]) - ord('A'))) % 26
            plain_char = chr(res + ord('A'))
            result += plain_char
            key += plain_char 
        else:
            result += cipher[i]
    return result


def main():
    while True:
        choice = input("Choose (1) Vigenere Encrypt, (2) Vigenere Decrypt, (3) Autokey Encrypt, (4) Autokey Decrypt: ")
        text = input("Enter text: ")
        key = input("Enter key: ")
        if choice == '1':
            print("Encrypted:", vigenere_encrypt(text, key))
        elif choice == '2':
            print("Decrypted:", vigenere_decrypt(text, key))
        elif choice == '3':
            print("Autokey Encrypted:", autokey_encrypt(text, key))
        elif choice == '4':
            print("Autokey Decrypted:", autokey_decrypt(text, key))
        elif choice == '5':
            print("Exiting...")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()