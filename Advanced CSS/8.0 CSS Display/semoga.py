from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import binascii

def encrypt(key, nonce, plaintext):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.encrypt(pad(plaintext, 16))

def decrypt(key, nonce, ciphertext):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return unpad(cipher.decrypt(ciphertext), 16)

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# Given data
key = os.urandom(16)
nonce = os.urandom(8)

plaintext1 = b"awok"
encrypted_plaintext1_hex = "3e9859c49ef047f7ae2f943483e57849"
encrypted_flag_hex = "1ca07bffd4b918af9315e371d9b62620d295d79a1f623a99230ecbac2469025de565da4be24e9da87a47af44d8c56681"

# Convert hex strings to bytes
encrypted_plaintext1 = binascii.unhexlify(encrypted_plaintext1_hex)
encrypted_flag = binascii.unhexlify(encrypted_flag_hex)

# Encrypt the known plaintext to find the keystream
cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
keystream = xor_bytes(pad(plaintext1, 16), encrypted_plaintext1[:16])

# Decrypt the flag using the keystream
decrypted_flag = xor_bytes(encrypted_flag[:16], keystream)

# Print the decrypted flag
print("Decrypted Flag:", decrypted_flag.decode())
