import hashlib

with open("dictionary.txt", "r") as f:
    passwords = f.read().splitlines()

with open("hashes.txt", "w") as f:
    for password in passwords:
        sha1_hash = hashlib.sha1(password.encode()).hexdigest()
        f.write(sha1_hash + "\n")


total_hashes = len(passwords)
cracked_hashes = set()

with open("recovered.txt", "r") as f:
    for line in f:
        if ":" in line:
            hash_part = line.split(":")[0].strip() 
            cracked_hashes.add(hash_part)  

success_rate = (len(cracked_hashes) / total_hashes) * 100

print(f"Total hashes: {total_hashes}")
print(f"Unique hashes cracked: {len(cracked_hashes)}")
print(f"Success rate: {success_rate:.2f}%")