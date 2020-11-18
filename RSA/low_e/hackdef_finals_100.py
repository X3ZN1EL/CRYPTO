#!/usr/bin/env python3

import gmpy2
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

# Extraccion de n y e 
with open('publica.pub') as f:
    key = RSA.importKey(f.read())

# Valores extraidos 
print("Valores extraidos: \n")
print("Valor de n: " + str(key.n) + "\n")
print("Valor de e: " + str(key.e) + "\n")

# Se abre la bandera en modo lectura de bytes con rb
F = open("bandera","rb").read()

# Se pasa la bandera de bytes a numeros obteniendo el ciphertext
c = bytes_to_long(F)

for i in range(1000):
    ans = gmpy2.iroot(c + i*key.n, key.e)[1]
    if ans == True:
        print("Iteracion: ", i)
        pt = int(gmpy2.iroot(c + i*key.n, key.e)[0])
        print(pt.to_bytes(43, 'big'))
        break
