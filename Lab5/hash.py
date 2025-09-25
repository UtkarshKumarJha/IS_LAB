def custom_hash(s: str) -> int:
    # Start with initial hash value
    h = 5381
    
    for ch in s:
        # Multiply by 33 and add ASCII value of char
        h = ((h * 33) + ord(ch)) & 0xFFFFFFFF  # Keep within 32-bit
    
    return h


# Example usage
if __name__ == "__main__":
    text = "HelloWorld"
    hval = custom_hash(text)
    print(f"Input: {text}")
    print(f"Hash value (32-bit): {hval}")
    print(f"Hash value (hex): {hval:08x}")
