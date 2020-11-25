#!/usr/bin/env python3

cadena = "label"
text = ""

for c in cadena:
    text += chr(ord(c)^13)

print("crypto{{{}}}".format(text))