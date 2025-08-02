import hashlib
import os
import time
from tqdm import tqdm

# --------- Helper Functions ---------

def identify_hash_type(hash_value):
    length = len(hash_value)
    if length == 32:
        return "md5"
    elif length == 40:
        return "sha1"
    elif 64 <= length <= 128:
        if length == 64:
            return "sha256"
        elif length == 128:
            return "sha512"
        else:
            return "sha256"  # tolerate in-between lengths as sha256
    else:
        return "unknown"

def hash_func(word, algo):
    if algo == "md5":
        return hashlib.md5(word.encode()).hexdigest()
    elif algo == "sha1":
        return hashlib.sha1(word.encode()).hexdigest()
    elif algo == "sha256":
        return hashlib.sha256(word.encode()).hexdigest()
    elif algo == "sha512":
        return hashlib.sha512(word.encode()).hexdigest()

def crack_single_hash(hash_value, algo, wordlist_path):
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for word in tqdm(f, desc=f"Cracking ({algo})", unit="word"):
            word = word.strip()
            if hash_func(word, algo) == hash_value:
                return word
    return None

def export_results(text):
    path = input("Enter filename to save results (or press Enter to skip saving): ").strip()
    if path:
        with open(path, "w") as f:
            f.write(text)
        print(f"[+] Results saved to {path}")

# --------- CLI Entry Point ---------

def main():
    print("🔐 Hash Identifier & Cracker [CLI VERSION]\n")

    use_file = input("Do you want to load hashes from file? (y/n): ").strip().lower() == 'y'
    
    hashes = []
    if use_file:
        hashlist_path = input("Enter path to hashlist file: ").strip()
        if not os.path.exists(hashlist_path):
            print("[-] Hashlist file not found.")
            return
        with open(hashlist_path, "r") as hf:
            hashes = [line.strip() for line in hf if line.strip()]
    else:
        single_hash = input("Enter a single hash: ").strip()
        if not single_hash:
            print("[-] No hash provided.")
            return
        hashes = [single_hash]

    wordlist_path = input("Enter path to wordlist file: ").strip()
    if not os.path.exists(wordlist_path):
        print("[-] Wordlist file not found.")
        return

    use_manual_algo = input("Do you want to manually select hash algorithm? (y/n): ").strip().lower() == 'y'
    if use_manual_algo:
        algo = input("Enter hash algorithm (md5/sha1/sha256/sha512): ").strip().lower()
        if algo not in ["md5", "sha1", "sha256", "sha512"]:
            print("[-] Invalid algorithm selected.")
            return

    cracked_results = []
    start_time = time.time()

    print(f"[+] Starting crack for {len(hashes)} hash(es)...")

    for h in hashes:
        algo_to_use = algo if use_manual_algo else identify_hash_type(h)
        if algo_to_use == "unknown":
            print(f"[-] Unknown hash type for: {h}")
            continue

        print(f"[*] Cracking {h[:10]}... ({algo_to_use.upper()})")
        try:
            cracked = crack_single_hash(h, algo_to_use, wordlist_path)
        except Exception as e:
            print(f"[-] Error cracking {h}: {e}")
            continue

        if cracked:
            print(f"[+] Found: {h} = {cracked}")
            cracked_results.append(f"{h} = {cracked}")
        else:
            print(f"[-] Not found: {h}")

    elapsed = time.time() - start_time
    print(f"\n[+] Done in {elapsed:.2f} seconds")
    print(f"[+] {len(cracked_results)} out of {len(hashes)} cracked")

    if cracked_results:
        export_results("\n".join(cracked_results))

if __name__ == "__main__":
    main()
