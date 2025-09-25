import hashlib
import random
import string
import time

# Function to generate random strings
def generate_random_strings(n, min_len=5, max_len=15):
    dataset = []
    for _ in range(n):
        length = random.randint(min_len, max_len)
        rand_str = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        dataset.append(rand_str)
    return dataset

# Function to compute hash using given algorithm
def compute_hash(algorithm, data):
    if algorithm == "MD5":
        return hashlib.md5(data.encode()).hexdigest()
    elif algorithm == "SHA1":
        return hashlib.sha1(data.encode()).hexdigest()
    elif algorithm == "SHA256":
        return hashlib.sha256(data.encode()).hexdigest()
    else:
        raise ValueError("Unsupported algorithm")

# Function to measure hashing performance
def analyze_performance(dataset, algorithms):
    results = {}
    for algo in algorithms:
        hashes = {}
        start_time = time.time()
        
        for data in dataset:
            h = compute_hash(algo, data)
            # Check for collisions
            if h in hashes and hashes[h] != data:
                print(f"[⚠️ Collision Detected] {algo}: '{data}' and '{hashes[h]}' -> {h}")
            hashes[h] = data
        
        end_time = time.time()
        results[algo] = {
            "time_taken": end_time - start_time,
            "unique_hashes": len(hashes),
            "total_inputs": len(dataset),
            "collisions": len(dataset) - len(hashes)
        }
    return results

if __name__ == "__main__":
    # Generate dataset of random strings
    dataset = generate_random_strings(random.randint(50, 100))
    algorithms = ["MD5", "SHA1", "SHA256"]

    print("🔹 Starting Hashing Experiment...\n")
    results = analyze_performance(dataset, algorithms)

    # Display results
    for algo, stats in results.items():
        print(f"\n=== {algo} Results ===")
        print(f"⏱️ Time Taken: {stats['time_taken']:.6f} seconds")
        print(f"📦 Total Inputs: {stats['total_inputs']}")
        print(f"🔑 Unique Hashes: {stats['unique_hashes']}")
        print(f"⚠️ Collisions: {stats['collisions']}")
