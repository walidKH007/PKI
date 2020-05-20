import socket, select
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from Crypto.Cipher import AES
import random
import os.path
from os import path
import datetime
import uuid
import pickle
from time import sleep
import glob

import sys
import hashlib
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

from OpenSSL import crypto
from OpenSSL.SSL import FILETYPE_PEM
from OpenSSL import SSL
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
import OpenSSL.crypto

from OpenSSL.crypto import load_certificate, load_privatekey
from OpenSSL.crypto import X509Store, X509StoreContext


## AES PassPhrass
cipher = AES.new('walidKHLOUF URCA')



def RemovePadding(s):
    return s.replace('`','')

##  to crypte long text
def Padding(str):
    return str + ((16-len(str) % 16) * '{')

    
def encrypt_message(plaintext):
    global cipher
    return cipher.encrypt(Padding(plaintext))

def decrypt_message(ciphertext):
    global cipher
    dec = cipher.decrypt(ciphertext)
    l = dec.count('{')
    return dec[:len(dec)-l]

    



buffer = 999999
port = 5001
host = "10.10.0.3"

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('', port))
server_socket.listen(10) #listen atmost 10 connection at one time

#print "\33[32m \tSERVER WORKING \33[0m" 

sock, addr = server_socket.accept()
msg_recev = sock.recv(buffer)

print("\n\33[33m message received successfully \33[0m")


decrypted_data = decrypt_message(msg_recev)
    
json_dictionary = pickle.loads(decrypted_data)


for key in json_dictionary:
    k = str(key)
    js = str(json_dictionary[key])
    if key == 'cetificate':
        with open(key+'.pem', "wb") as csrfile:
            csrfile.write(js)
    else: 
        with open(key+'.txt', "wb") as csrfile:
            csrfile.write(js)

with open('cetificate.pem', "rb") as f:
    cert_data =  x509.load_pem_x509_certificate(f.read(), default_backend())

with open('message.txt', "rb") as f:
    message =  f.read()

with open('Signature.txt', "rb") as f:
    sig =  base64.b64decode(f.read())



public_key = cert_data.public_key()

try:
    public_key.verify(
            sig,
            hashlib.sha256(message).hexdigest(),
            padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
    print("\n\33[32m valid Message\33[0m")
    

except InvalidSignature:
    print("\33[32m invalid Massage \33[0m")
    

server_socket.close()





























