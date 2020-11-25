#!/usr/bin/env python3

from base64 import b64decode

cipher_text = open("file.txt","r").read().strip()

for i in range(25):
    cipher_text = b64decode(cipher_text)

print(cipher_text)
