from tinyec import registry
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def generate_keypair(curve):
    private_key = int.from_bytes(get_random_bytes(32), byteorder="big") % curve.field.n
    public_key = private_key * curve.g
    return private_key, public_key

def derive_shared_secret(private_key, public_key):
    shared_secret = private_key * public_key
    return int.from_bytes(shared_secret.x.to_bytes(32, byteorder="big"), byteorder="big")

def encrypt_file(filename, shared_secret):
    key = shared_secret.to_bytes(32, byteorder="big")
    cipher = AES.new(key, AES.MODE_EAX)
    
    with open(filename, "rb") as file:
        plaintext = file.read()
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    with open(filename + ".enc", "wb") as file:
        file.write(cipher.nonce)
        file.write(tag)
        file.write(ciphertext)

def decrypt_file(filename, shared_secret):
    key = shared_secret.to_bytes(32, byteorder="big")
    
    with open(filename, "rb") as file:
        nonce = file.read(16)
        tag = file.read(16)
        ciphertext = file.read()
    
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    
    with open(filename.replace(".enc", "_decrypted.txt"), "wb") as file:
        file.write(plaintext)

if __name__ == "__main__":
    # Using secp256r1 curve (P-256)
    curve = registry.get_curve("secp256r1")

    # Alice generates key pair
    alice_private_key, alice_public_key = generate_keypair(curve)
    
    # Bob generates key pair
    bob_private_key, bob_public_key = generate_keypair(curve)

    # Alice derives shared secret from Bob's public key
    alice_shared_secret = derive_shared_secret(alice_private_key, bob_public_key)

    # Bob derives shared secret from Alice's public key
    bob_shared_secret = derive_shared_secret(bob_private_key, alice_public_key)

    # Encrypt and decrypt a sample file using the shared secrets
    sample_file = "sample.txt"
    with open(sample_file, "w") as file:
        file.write("Malware Development for Ethical Hackers =^..^=")

    encrypt_file(sample_file, alice_shared_secret)
    decrypt_file(sample_file + ".enc", bob_shared_secret)
