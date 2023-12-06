import hashlib

def calc_md5(data):
    md5_hash = hashlib.md5()
    md5_hash.update(data)
    return md5_hash.hexdigest()

def main():
    input_data = b'meow-meow'
    md5_hash = calc_md5(input_data)

    print(f"MD5 Hash: {md5_hash}")

if __name__ == "__main__":
    main()
