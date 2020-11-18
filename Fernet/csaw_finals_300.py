#!/usr/bin/env python3

from cryptography.fernet import Fernet
from base64 import b64encode

key = 'xYDFDoqcOACPKeT5gT0wBzAfBSoGieVc' 
key_fernet = b64encode(key)
f = Fernet(key_fernet)
print(f.decrypt('gAAAAABfprGds2-Sl4iF5BMjjotnTDKFPsfL8AtJOOeeruqB4w8RGk5gNUt0JM0q2xDve9x9PNHkNkk7f9rf1LekcIBjT1MHIIrvIlnhGqunRRwX59Eo42M='))

