#!/usr/bin/env python3

from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import owiener

with open('pubkey.pem') as f:
    key = RSA.importKey(f.read())

# Valores extraidos 
print("Valores extraidos: \n")
print("Valor de n: " + str(key.n) + "\n")
print("Valor de e: " + str(key.e) + "\n")

n = key.n
e = key.e

# Se abre la bandera en modo lectura de bytes con rb
F = open("flag.enc","rb").read()

# Se pasa la bandera de bytes a numeros obteniendo el ciphertext
c = bytes_to_long(F)

d = owiener.attack(e,n)

message = pow(c,d,n)

print(long_to_bytes(message))