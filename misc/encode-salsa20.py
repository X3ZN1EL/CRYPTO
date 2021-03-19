#!/usr/bin/env python3
# xen was here

from Crypto.Cipher import Salsa20
import secrets

plaintext = b'Hola mundo'
secret= secrets.token_bytes(32)
print(secret)
cipher = Salsa20.new(key=secret)
msg = cipher.nonce + cipher.encrypt(plaintext)
print(msg)
