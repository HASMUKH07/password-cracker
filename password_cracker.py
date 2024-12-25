import hashlib
import itertools
import time
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

# Utility function to hash a password using a given algorithm
def hash_password(password, algorithm="sha256"):
    try:
        hasher = hashlib.new(algorithm)
        hasher.update(password.encode('utf-8'))
        return hasher.hexdigest()
    except ValueError:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}. Supported algorithms are: {', '.join(hashlib.algorithms_available)}")

# Automatically detect hash algorithm
def detect_hash_algorithm(hash_to_crack):
    test_password = "test"
    for algorithm in hashlib.algorithms_available:
        try:
            test_hash = hash_password(test_password, algorithm)
            if len(test_hash) == len(hash_to_crack):
                return algorithm
        except ValueError:
            continue
    return None

# Dictionary attack function
def dictionary_attack(hash_to_crack, wordlist_path, algorithm):
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                password = line.strip()
                hashed_password = hash_password(password, algorithm)
                if hashed_password == hash_to_crack:
                    return password
    except FileNotFoundError:
        print("[!] Wordlist file not found!")
    return None

# Brute-force attack function
def brute_force_attack(hash_to_crack, max_length, charset, algorithm):
    for length in range(1, max_length + 1):
        for combination in itertools.product(charset, repeat=length):
            password = ''.join(combination)
            hashed_password = hash_password(password, algorithm)
            if hashed_password == hash_to_crack:
                return password
    return None

# Threaded brute-force attack function
def threaded_brute_force(hash_to_crack, max_length, charset, algorithm, threads=4):
    def worker(start, step):
        for length in range(1, max_length + 1):
            for i, combination in enumerate(itertools.product(charset, repeat=length)):
                if i % step != start:
                    continue
                password = ''.join(combination)
                hashed_password = hash_password(password, algorithm)
                if hashed_password == hash_to_crack:
                    return password

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(worker, i, threads) for i in range(threads)]
        for future in futures:
            result = future.result()
            if result:
                return result
    return None

# Automated attack function
def automated_attack(hash_to_crack, wordlist_path, max_length, charset, threads=4):
    print("[*] Detecting hash algorithm...")
    algorithm = detect_hash_algorithm(hash_to_crack)
    if not algorithm:
        print("[!] Unable to detect hash algorithm. Exiting...")
        return None
    print(f"[+] Detected hash algorithm: {algorithm}")

    print("[*] Trying dictionary attack...")
    result = dictionary_attack(hash_to_crack, wordlist_path, algorithm)
    if result:
        return result

    print("[*] Trying brute-force attack with single-thread...")
    result = brute_force_attack(hash_to_crack, max_length, charset, algorithm)
    if result:
        return result

    print("[*] Trying multi-threaded brute-force attack...")
    result = threaded_brute_force(hash_to_crack, max_length, charset, algorithm, threads)
    return result

# Main function
def main():
    print("Advanced Password Cracking Toolkit")

    # Input hash to crack
    hash_to_crack = input("Enter the hash to crack: ")

    # Input wordlist path
    wordlist_path = input("Enter the path to the wordlist (default: rockyou.txt): ").strip() or "rockyou.txt"

    # Input maximum password length
    max_length = int(input("Enter the maximum password length for brute force (default: 5): ").strip() or 5)

    # Dynamic charset expansion
    charsets = {
        "numbers": "0123456789",
        "lowercase": "abcdefghijklmnopqrstuvwxyz",
        "uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "special": "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~"
    }
    charset = input(
        "Enter the character set (default: numbers+lowercase+uppercase+special): ").strip() or \
              charsets["numbers"] + charsets["lowercase"] + charsets["uppercase"] + charsets["special"]

    # Number of threads for multi-threaded brute force
    threads = int(input("Enter the number of threads for brute force (default: 4): ").strip() or 4)

    # Start cracking process
    start_time = time.time()
    result = automated_attack(hash_to_crack, wordlist_path, max_length, charset, threads)
    elapsed_time = time.time() - start_time

    if result:
        print(f"[+] Password found: {result} in {elapsed_time:.2f} seconds")
    else:
        print("[-] Password not found.")

if __name__ == "__main__":
    main()
