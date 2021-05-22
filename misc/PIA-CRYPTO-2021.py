#!/usr/bin/env python3

import random
from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
import binascii

# VALIDAR INPUT
def validar(response):
    try:
        temp = int(response)
        return True
    except:
        pass

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

# ENCRYPT AES
def encrypt(plain_text):
    # RANDOM KEY
    key = ''.join(chr(random.randint(0, 0xFF)) for i in range(16)).encode('utf-8')
    # Genera un random salt
    salt = get_random_bytes(AES.block_size)
    # Usa un KDF para generar la llave
    private_key = hashlib.scrypt(
        key, salt=salt, n=2**14, r=8, p=1, dklen=32)
    # Inicia el modo de operacion
    cipher_config = AES.new(private_key, AES.MODE_GCM)
    # Crea el dic cifrado
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8'))
    return {
        'cipher_text': b64encode(cipher_text).decode('utf-8'),
        'key': b64encode(key).decode(),
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }

# DECRYPT AES
def decrypt(enc_dict,key):
    # Hace el decode del dic cifrado
    k = b64decode(key)
    salt = b64decode(enc_dict['salt'])
    cipher_text = b64decode(enc_dict['cipher_text'])
    nonce = b64decode(enc_dict['nonce'])
    tag = b64decode(enc_dict['tag'])
    # Genera un salt en la llave
    private_key = hashlib.scrypt(
        k, salt=salt, n=2**14, r=8, p=1, dklen=32)
    # Inicia el modo de operacion
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)
    # Hace el decrypt
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)
    return decrypted

# CARTA 
message = input("carta: ")
message_enc_json = encrypt(message)

# AES DATA
aes_msg = message_enc_json['cipher_text']
aes_key = message_enc_json['key']

# CARTA CIFRADA
print("\nCarta cifrada:")
print(aes_msg)

# AES KEY ENVELOPE
print("\nEnvelope: ")
rsa_enc_key = rsa_envelope(aes_key.encode())
print(rsa_enc_key)

response_user = input("\nQuieres saber que dice?\ns/n\n -> ")

if response_user == str('s'):
    print("\nResponde la pregunta correctamente")
    num1 = random.randint(1,10000)
    num2 = random.randint(1,10000)

    aritmetic_quest = input("Cuanto es " + str(num1) + " + " + str(num2) + " ? \n -> ")

    if validar(aritmetic_quest):

        if int(aritmetic_quest) == num1 + num2:
            print("\nRespuesta correcta!")
            envelope_verification = int(input("Ingresa el envelope\n -> "))

            if validar(envelope_verification):
                if int(envelope_verification) == rsa_enc_key:
                    print("\nRespuesta correcta!")
                    key_decrypt = decrypt_envelope(int(envelope_verification))
                    print("\nCarta: ")
                    carta_dec = decrypt(message_enc_json,key_decrypt).decode()
                    print(carta_dec)
                else:
                    print("nope!")
        else:
            print("nope!")
else:
    print("Bye!")
