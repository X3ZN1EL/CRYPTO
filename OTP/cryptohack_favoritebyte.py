#!/usr/bin/env python3

import binascii

def decode_xor(data, key):
    text = b''
    for c in data:
        text += bytes([c ^ key])
    try:
        return text.decode("utf-8")
    except:
        return "Cannot Decode some bytes"

data = "73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d"
data_decode = binascii.unhexlify(data)

# NO DECODEAR ASI
# data_decode = bytes.fromhex(data).decode('utf-8')

result = {}
for i in range(256):
    result[i] = decode_xor(data_decode, i)

print(([c for c in result.values() if "crypto{" in c]))



