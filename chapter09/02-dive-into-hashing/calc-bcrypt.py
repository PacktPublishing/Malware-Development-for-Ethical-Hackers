import bcrypt

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

# Example Usage
password_to_hash = "mysupersecretpassword"
hashed_password = hash_password(password_to_hash)
print(f"Hashed Password: {hashed_password.decode('utf-8')}")