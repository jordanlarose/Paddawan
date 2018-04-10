#! usr/bin/env python

# This is a Proof of Concept of a basic AES-CBC encryption scheme with 16 byte
# padding. The comments below will explain how it works.
from Crypto.Cipher import AES

# These values are what we're trying to reverse-engineer in a padding oracle
# attack. For our purposes, they are arbitrary.
key = "aaaabbbbccccdddd"
iv = "1111222233334444"

# This is our simple decryption function. It takes the encryption key and our
# encryption scheme and applies those to an encrpyted value to get the
# decrypted value
def decr(ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return ispkcs7(cipher.decrypt(ciphertext))

# This function checks to make sure that we're trying to decrypt has the
# correct amount of bytes (padding). This function telling users that they have
# incorrect padding is what allows us to perform a padding oracle attack.
def ispkcs7(plaintext):
    l = len(plaintext)
    c = ord(plaintext[l-1])                       
    if (c > 16) or (c < 1):
      return "PADDING ERROR"
    if plaintext[l-c:] != chr(c)*c:
      return "PADDING ERROR"
    return plaintext

# This is the inverse of our above encryption function.
def encr(plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pkcs7(plaintext))
    return ciphertext

# This last bit is the standard we use to pad our bytes during encryption. For
# more info on how this encryption actually works, see the Crypto.Cipher
# documentation.
def pkcs7(plaintext):
    padbytes = 16 - len(plaintext) % 16
    pad = padbytes * chr(padbytes)
    return plaintext + pad 
