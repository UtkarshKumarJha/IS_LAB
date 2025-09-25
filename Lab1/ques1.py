def additive_encrypt(text,key):
    text = text.upper()
    return "".join([chr(((ord(c)-65+key)%26)+65) for c in text])

def additive_decrypt(cipher,key):
    return "".join([chr(((ord(c)-65-key)%26)+65) for c in cipher])

def multi_encrypt(text,key):
    text = text.upper()
    return "".join([chr((((ord(c)-65)*key)%26)+65) for c in text])

def mod_inv(a,m):
    for x in range(1,m):
        if((a*x)%m==1):
            return x
    return None

def multi_decrypt(cipher,key):
    return "".join([chr((((ord(c)-65)*mod_inv(key,26))%26)+65) for c in cipher])

def affine_encrypt(text,a,b):
    text = text.upper()
    return "".join([chr(((a*(ord(c)-65)+b)%26)+65) for c in text])

def affine_decrypt(cipher,a,b):
    return "".join([chr(((mod_inv(a,26)*(ord(c)-65-b))%26)+65) for c in cipher])

def main():
    while True:
        print("1. Additive")
        print("2. Multiplicative")
        print("3. Affine")
        print("4. Exit")
        choice = input("Enter your choice: ")
        if choice == '1':
            text = input("Enter text to encrypt: ")
            encrypted = additive_encrypt(text, 20)
            print("Encrypted:", encrypted)
            decrypted = additive_decrypt(encrypted, 20)
            print("Decrypted:", decrypted)
        elif choice == '2':
            cipher = input("Enter text to decrypt: ")
            encrypted = multi_encrypt(cipher, 15)
            print("Encrypted:", encrypted)
            decrypted = multi_decrypt(encrypted, 15)
            print("Decrypted:", decrypted)
        elif choice == '3':
            text = input("Enter text to encrypt: ")
            encrypted = affine_encrypt(text, 15, 20)
            print("Encrypted:", encrypted)
            decrypted = affine_decrypt(encrypted, 15, 20)
            print("Decrypted:", decrypted)
        elif choice == '4':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
