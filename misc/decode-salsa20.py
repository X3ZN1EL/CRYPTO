#!/usr/bin/env python3

from Crypto.Cipher import Salsa20

secret = b'\xc7\x0f\xe7;"\x9c\xe2\xabU\x1c(C}y\xb2\xd91\xda\xc6I\xd4h\xd18h,\xfb\x7f\x1f\xac\x8e\x00'
msg = b'4\xd5\xd8\x83\x90\x93\x80\xcc\xaa&\xab\xedN\x91\x0c%\xb8\x82'
msg_nonce = msg[:8]
ciphertext = msg[8:]
cipher = Salsa20.new(key=secret, nonce=msg_nonce)
plaintext = cipher.decrypt(ciphertext)
print(plaintext)
