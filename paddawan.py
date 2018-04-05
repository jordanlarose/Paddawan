#!/usr/bin/env python
##This file should explain how a basic padding oracle attack works against a CBC encryption scheme. We start by importing our AES CBC encryption and decrption functions, and creating a control string to manipulate.
from padme import encr, decr
a = "Help me Obi-Wan Kenobi. You are my only."
control = encr(a)

##Let's start by looking at the encrypted string as hex values. One important thing to note is that this encryption scheme encrypts bytes in blocks of 16, which we will need to know for a successful padding attack
print control.encode("hex")

##Now, let's try appending a series of characters to the second block of encrypted bytes
#for i in range(5):
#  mod = control[0:31] + chr(i) + control[32:]
#  print mod.encode("hex")
#  print i, decr(mod)

##Next, let's iterate through every possible character, and try to find the characters that don't return padding errors
#for i in range(256):
#  mod = control[0:31] + chr(i) + control[32:]
#  if decr(mod) != "PADDING ERROR":
#    print mod.encode("hex")
#    print i, "for byte 32 is correctly padded"

##Using this method, we'll get two valid results. This is because one of them is the original byte (204), and the other (197) is the intialization vector for our padding byte, 1
#print ord(control[31])

##To remove the original byte from our results, we can change the second block of bytes to junk, minus the byte we're targeting, 32:
#prefix = control[0:16] + "AAAAAAAAAAAAAAA"
#print prefix.encode("hex")
#for i in range(256):
#  mod = prefix + chr(i) + control[32:]
#  if decr(mod) != "PADDING ERROR":
#    print i, "for byte 32 is correctly padded"

##This will work with any string, since we aren't changing the byte that we're targeting, 32
#prefix = control[0:16] + "BBBBBBBBBBBBBBB"
#for i in range(256):
#  mod = prefix + chr(i) + control[32:]
#  if decr(mod) != "PADDING ERROR":
#    print i, "for byte 32 is correctly padded"

##Now that we know the correct value for byte 31 to XOR to 1 from (196), we can use it to create a loop that finds the valid padding for bytes 30 and 31, which need to XOR to 2. 196 is our byte value, so we XOR that ^2 to get our byte 32 value 
#prefix = control[0:16] + "BBBBBBBBBBBBBB"
#for i in range(256):
#        mod = prefix + chr(i) + chr(196^2) + control[32:]
#        if decr(mod) != "PADDING ERROR":
#            print i, "for byte 31 is correctly padded"

##Now we add an additional byte of padding, and increment our known values' XOR
#prefix = control[0:16] + "BBBBBBBBBBBBB"
#for i in range(256):
#    mod = prefix + chr(i) + chr(70^3) + chr(196^3) + control[32:]
#    if decr(mod) != "PADDING ERROR":
#        print i, "for byte 30 is correctly padded"

##At this point, we can continue decrypting bytes until we reach the first block, as we cannot reverse its initialization vector
#prefix = control[0:16] + "BBBBBBBBBBBB"
#for i in range(256):
#  mod = prefix + chr(i) + chr(13^4) + chr(70^4) + chr(196^4) + control[32:]
#  if decr(mod) != "PADDING ERROR":
#    print i, "for byte 29 is correctly padded"

##One more for good measure
#prefix = control[0:16] + "BBBBBBBBBBB"
#for i in range(256):
#    mod = prefix + chr(i) + chr(52^5) + chr(13^5) + chr(70^5) + chr(196^5) + control[32:]
#    if decr(mod) != "PADDING ERROR":
#        print i, "for byte 28 is correctly padded"

##Now that we know the byte values, we can insert whatever we want into the encrypted bytes, since XOR is reversible. Let's change the end of the encrypted string to hope and decrypt it
#byte32 = 196^1
#byte31 = ord("e") ^ 70
#byte30 = ord("p") ^ 13
#byte29 = ord("o") ^ 52
#byte28 = ord("h") ^ 205
#ciphertext = control[0:27] + chr(byte28) + chr(byte29) + chr(byte30) + chr(byte31) + chr(byte32) + control[32:]
#print(decr(ciphertext))
