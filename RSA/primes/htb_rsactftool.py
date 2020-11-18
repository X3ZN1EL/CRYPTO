#!/usr/bin/env python3

from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

# Extraccion de n y e 
with open('pubkey.pem') as f:
    key = RSA.importKey(f.read())

# Valores extraidos 
print("Valores extraidos: \n")
print("Valor de n: " + str(key.n) + "\n")
print("Valor de e: " + str(key.e) + "\n")

n = key.n 
e = key.e

# Calculo de totient usando Alperton
totient = 1128137999850045612492145429133282716267233566834715456536184965477269592934207986950131365518741418540788596074115883774105736493742449131477464976858161478985873203046725684762542703276327115788655794113995287824514072024731568597924825265729337653184382887723246889395509134091865411387959116471599230373246445278136146505138709064280336097539869381527099308498586034471695597580120874039115434749770630625131717511959100713950159447864644197127349977350413110
print("Valor de totient: " + str(totient) + "\n")

# Calculo de variable d
d = inverse(key.e,totient)
print("Valor de d: " + str(d) + "\n")

# Lectura de llave
with open("key") as f:
    key = f.read()

key = bytes_to_long(bytes.fromhex(key))
key = long_to_bytes(pow(key,d,n))
print("LLave: " + str(key))

# Formato de cifrado
cipher = AES.new(key, AES.MODE_ECB)

# Lectura de flag en bytes
with open("flag.txt.aes", "rb") as f:
    flag = f.read().strip()

# decrypt AES

decrypted = cipher.decrypt(flag)
print("Flag: " + str(decrypted))






