"""
High level overview.

1) Read in wallet
2) For each password in a password file, do the rest of the steps.
3) Decrypt wallet with given password
4) If decryption succeeds, check that hash of seed is correct.
5) If hash is correct, spit out the password (and seed).
"""

from sys import argv, stdin
import json
import binascii
from python_sha3 import sha3_256
from pbkdf2 import _pbkdf2 as pbkdf2

from Crypto.Cipher import AES

def load_wallet(wallet_file):
    with open(wallet_file) as f:
        return json.load(f)

def kdf(password):
    return pbkdf2(password, password, 2000)[:16]

def gen_bkp(seed):
    return sha3_256(b'' + seed + b'\0x02').hexdigest()

def unpad(plain):
    # Detect nvalid padding early.
    if plain[-1] > 16:
        return None
    return plain[0:-plain[-1]]

def decrypt(password, encrypted_seed, iv, seed_hash):
    key = kdf(password)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    seed = unpad(cipher.decrypt(encrypted_seed))
    if seed is None:
        return None
    bkp = gen_bkp(seed)
    if sha3_256(seed + b'\x02').hexdigest() == seed_hash:
        return seed
    else:
        return None

def main():
    if len(argv) != 2:
        print('Usage: cat password_file | ethcrack.py wallet_file')
        return
    wallet_file = argv[1]

    wallet = load_wallet(wallet_file)
    encrypted_seed_with_iv = binascii.unhexlify(wallet['encseed'])
    iv = encrypted_seed_with_iv[:16]
    encrypted_seed = encrypted_seed_with_iv[16:]
    seed_hash = wallet['bkp']

    for i, password in enumerate(stdin):
        # Strip trailing newline
        password = password[:-1]
        if i % 1000 == 0:
            print(i)
        seed = decrypt(password, encrypted_seed, iv, seed_hash)
        if seed is not None:
            print('Found password: %s' % password)
            print('Seed: %s' % binascii.hexlify(seed))
            return
    print('Could not find valid password.')

if __name__ == '__main__':
    main()
