def gen_key_matrix(keyword):
    keyword = keyword.upper().replace("J","I")
    matrix = []
    seen = set()
    
    for ch in keyword:
        if ch not in seen and ch.isalpha():
            matrix.append(ch)
            seen.add(ch)
            
    for ch in range(65,91):
        if chr(ch) not in seen and chr(ch) != 'J':
            matrix.append(chr(ch))
            seen.add(chr(ch))
    
    for i in range(5):
        for j in range(5):
            print(matrix[i*5 + j], end=' ')
            
    return [matrix[i*5:(i+1)*5] for i in range(5)]

def preprocess_text(text):
    text = text.upper().replace("J","I")
    text = ''.join(ch for ch in text if ch.isalpha())
    processed = []
    i=0
    while i<len(text):
        a = text[i]
        if i+1 < len(text):
            b = text[i+1]
            if a==b:
                processed.append(a+"X")
                i+=1
            else:
                processed.append(a+b)
                i+=2
        else:
            processed.append(a+"X")
            i+=1
    return processed

def find_pos(matrix,ch):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == ch:
                return r,c
    return None

def encrypt_pairs(matrix,a,b):
    r1,c1 = find_pos(matrix,a)
    r2,c2 = find_pos(matrix,b)
    if r1 == r2:
        return matrix[r1][(c1+1)%5]+ matrix[r2][(c2+1)%5]
    elif c1 == c2:
        return matrix[(r1+1)%5][c1]+matrix[(r2+1)%5][c2]
    else:
        return matrix[r1][c2]+matrix[r2][c1]
    
def decrypt_pairs(matrix,a,b):
    r1,c1 = find_pos(matrix,a)
    r2,c2 = find_pos(matrix,b)
    if r1 == r2:
        return matrix[r1][(c1-1)%5]+ matrix[r2][c2-1%5]
    elif c1 == c2:
        return matrix[(r1-1)%5][c1]+matrix[(r2-1)%5][c2]
    else:
        return matrix[r1][c2]+matrix[r2][c1] 

def playfair_encrypt(key,plain):
    matrix = gen_key_matrix(key)
    pairs = preprocess_text(plain)
    cipher_pairs = [encrypt_pairs(matrix,a[0],a[1]) for a in pairs]
    cipher = ''.join(cipher_pairs)
    return cipher,cipher_pairs,matrix

def playfair_decrypt(key,cipher):
    matrix = gen_key_matrix(key)
    pairs = [cipher[i:i+2] for i in range(0,len(cipher),2)]
    plain_pairs = [decrypt_pairs(matrix,a[0],a[1]) for a in pairs]
    plain = ''.join(plain_pairs)
    return plain,plain_pairs,matrix
    
if __name__ == "__main__":
    key = input("Enter keyword:")
    plain = input("Enter plaintext:")
    cipher,cipher_pairs,matrix = playfair_encrypt(key,plain)
    print("Ciphertext:",cipher)
    print("Cipher Pairs:",cipher_pairs)
    