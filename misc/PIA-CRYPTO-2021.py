#!/usr/bin/env python3 
# xen was here

import random
from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
import binascii

# KEYS GENERATION
# openssl genrsa -out private-key.pem 2048
# openssl rsa -in private-key.pem -pubout -out public-key.pem

# RSA ENCRYPT
def rsa_envelope(aes_key):

    with open('keys/public-key.pem') as f:
        pub_key = RSA.importKey(f.read())

    with open('keys/private-key.pem') as t:
        priv_key = RSA.import_key(t.read())
    
    msg = binascii.hexlify(aes_key)
    m = int(msg,16)
    c = m ** pub_key.e % pub_key.n
    return c 

# RSA DECRYPT
def decrypt_envelope(cipher_key):

    with open('keys/public-key.pem') as f:
        pub_key = RSA.importKey(f.read())

    with open('keys/private-key.pem') as t:
        priv_key = RSA.import_key(t.read())

    message = pow(cipher_key,priv_key.d,pub_key.n)
    clear_key = long_to_bytes(message).decode()
    return clear_key

# RANDOM KEY
key = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))

# ENCRYPT AES
def encrypt(plain_text, key):
    # Genera un random salt
    salt = get_random_bytes(AES.block_size)
    # Usa un KDF para generar la llave
    private_key = hashlib.scrypt(
        key.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    # Inicia el modo de operacion
    cipher_config = AES.new(private_key, AES.MODE_GCM)
    # Crea el dic cifrado
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8'))
    return {
        'cipher_text': b64encode(cipher_text).decode('utf-8'),
        'key': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }

# DECRYPT AES
def decrypt(enc_dict, key):
    # Hace el decode del dic cifrado
    salt = b64decode(enc_dict['key'])
    cipher_text = b64decode(enc_dict['cipher_text'])
    nonce = b64decode(enc_dict['nonce'])
    tag = b64decode(enc_dict['tag'])
    # Genera un salt en la llave
    private_key = hashlib.scrypt(
        key.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    # Inicia el modo de operacion
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)
    # Hace el decrypt
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)
    return decrypted

# CARTA 
message1 = input("carta: ")
message1_enc_json = encrypt(message1,key)

# CARTA CIFRADA
print("\nCarta cifrada:")
ciphertext = message1_enc_json['cipher_text']
print(ciphertext)

# AES KEY CIFRADA
print("\nEnvelope: ")
aes_key_envelope= message1_enc_json['key']
result_key_envelope = rsa_envelope(aes_key_envelope.encode())
print(result_key_envelope)

# USER INTERACTION

response_user = input("\nQuieres saber que dice?\ns/n\n -> ")
if response_user == "s":
    print("\nResponde la pregunta correctamente")
    num1 = random.randint(1,10000)
    num2 = random.randint(1,10000)
    seg_q = int(input("Cuanto es " + str(num1) + " + " +str(num2) + " ? \n -> "))

# SECURITY QUESTION
    if seg_q == num1 + num2:
        print("\nRespuesta correcta!") 
        envelope_verification = int(input("Ingresa el envelope\n -> "))

        # ENVELOPE VERIFICATION
        if envelope_verification == result_key_envelope:
            print("\nRespuesta correcta!")
            dec_carta = decrypt(message1_enc_json,key)
            print("Carta: "  + dec_carta.decode())
        else:
            print("nope!") 
    else:
        print("nope!")
    
elif response_user == "n":
    print("bye!")