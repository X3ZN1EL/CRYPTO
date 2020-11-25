#!/usr/bin/env python3

from base64 import b64decode
from pwn import *

ciphertext = open("roxy.txt","r").read().strip()
#print(ciphertext)

decode_b64 = b64decode(ciphertext)
print(xor(decode_b64,"flag{XOR_es_el_101_d_crypto}")) #flag{XOR_es_el_101_d_crypto}

