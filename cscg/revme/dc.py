#! /bin/python
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad

#Flag 1
def decrypt1(ciphertext, secretKey, iv):
    aesCipher = AES.new(secretKey, AES.MODE_CBC, iv)
    plaintext = aesCipher.decrypt(base64.b64decode(ciphertext))
    return plaintext.decode("utf-16")

text = "A_Wise_Man_Once_Told_Me_Obfuscation_Is_Useless_Anyway"
salt = b"Ivan Medvedev"

ciphertext = "D/T9XRgUcKDjgXEldEzeEsVjIcqUTl7047pPaw7DZ9I="
ciphertext.replace(" ","+")

key = PBKDF2(text, salt, dkLen=48)
iv = key[32:]
key = key [:32]
print("Flag1: {}".format(decrypt1(ciphertext,key,iv)))