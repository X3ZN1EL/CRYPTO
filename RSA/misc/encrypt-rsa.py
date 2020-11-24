#!/usr/bin/env python3 
# xeniel was here

import gmpy2
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
import binascii

msg = binascii.hexlify(b'Mensaje para FCFM')
p = getPrime(1024)
q = getPrime(1024)
n = p*q
e = 17
t = (p-1)*(q-1)
d = gmpy2.invert(e, t)
m = int(msg,16)
c = m ** e % n
print("p: " + str(p) + "\n")
print("q: " + str(q) + "\n")
print("n: " + str(n) + "\n")
print("e: " + str(e) + "\n")
print("t: " + str(t) + "\n")
print("d: " + str(d) + "\n")
print("m: " + str(m) + "\n")
print("c: " + str(c) + "\n")