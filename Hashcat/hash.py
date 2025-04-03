import hashlib

with open("dictionary.txt", "r") as f:
    passwords = f.read().splitlines()

original_hashes = {}
for password in passwords:
    sha1_hash = hashlib.sha1(password.encode()).hexdigest()
    original_hashes[sha1_hash] = password

total_hashes = len(original_hashes)


recovered_hash_set = set()
with open("recovered.txt", "r") as f:
    for line in f:
        if ":" in line:
            hash_part = line.split(":")[0].strip() 
            recovered_hash_set.add(hash_part)  

recovered_success = (len(recovered_hash_set) / total_hashes) * 100

print(f"Total unique hashes to crack: {total_hashes}")
print(f"Unique hashes in recovered.txt: {len(recovered_hash_set)}")
print(f"Success rate (recovered.txt): {recovered_success:.2f}%")


cracked_hashes = {}

with open("cracked.txt", "r") as f:
    for line in f:
        if ":" in line:
            hash_part = line.split(":")[0].strip()
            password_part = line.split(":")[1].strip()
            cracked_hashes[hash_part] = password_part


cracked_count = sum(1 for h in original_hashes if h in cracked_hashes)
cracked_success = (cracked_count / total_hashes) * 100

print(f"\nUnique hashes in cracked.txt: {len(cracked_hashes)}")
print(f"Original hashes successfully cracked: {cracked_count}")
print(f"Success rate (cracked.txt): {cracked_success:.2f}%")

