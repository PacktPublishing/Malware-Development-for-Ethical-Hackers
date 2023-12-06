import hashlib

def sha1_hash(data):
    sha1 = hashlib.sha1()
    sha1.update(data.encode('utf-8'))
    return sha1.hexdigest()

# Example Usage
data_to_hash = "Hello, World!"
hashed_data = sha1_hash(data_to_hash)
print(f"SHA-1 Hash: {hashed_data}")
