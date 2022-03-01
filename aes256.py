# AES 256 encryption/decryption using pycrypto library
 
import base64
from Crypto.Cipher import AES
 
BLOCK_SIZE = 16
PASSWORD_SIZE = 32

password = "crime"
filler = "\x00"
 
def decrypt(enc, password):
    enc = base64.b64decode(enc)
    iv = ''
    while len(iv) < BLOCK_SIZE:
        iv += filler
    cipher = AES.new(password.encode(), AES.MODE_CBC, iv.encode())
    return cipher.decrypt(enc)
 
 
encrypted = "bBEUGZApdn9AWs3qKeG+iQ=="
 
while len(password) < PASSWORD_SIZE:
    password += filler
decrypted = decrypt(encrypted, password)
print(decrypted.decode())