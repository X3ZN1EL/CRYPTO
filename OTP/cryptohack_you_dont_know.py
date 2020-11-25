#!/usr/bin/env python3

import binascii
from pwn import *

msg = "0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104"

decode_msg = binascii.unhexlify(msg)
print(decode_msg)

print(xor(decode_msg,"crypto{".encode())) # myXORkey
key = "myXORKey"
plaintext = (xor(decode_msg,key))

print(plaintext.decode('utf-8'))


