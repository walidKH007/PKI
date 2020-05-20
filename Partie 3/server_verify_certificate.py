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

print "\33[32m \tSERVER WORKING \33[0m" 

sock, addr = server_socket.accept()
msg=sock.recv(buffer)

print "\n\33[32m certificate successfully received \33[0m"


decrypted_data = decrypt_message(msg)
	
json_dictionary = pickle.loads(decrypted_data)


for key in json_dictionary:
	k = str(key)
	js = str(json_dictionary[key])
	with open('verify_cert_'+key+'.pem', "wb") as csrfile:
			csrfile.write(js)
	
with open('verify_cert_cetificate.pem', "rb") as f:
	cert_data =  load_certificate(crypto.FILETYPE_PEM, f.read())

with open("cert/RootCA.pem",'rb') as f:
            #root_cert =  x509.load_pem_x509_certificate(f.read(), default_backend())
        root_cert = load_certificate(crypto.FILETYPE_PEM, f.read())



store = X509Store()
store.add_cert(root_cert)


store_ctx = X509StoreContext(store, cert_data)
verify = str(store_ctx.verify_certificate())


if verify == "None":
	sock.send(encrypt_message("valid"))
else:
	sock.send(encrypt_message('invalid'))

print "\n\33[32m verification done ! \33[0m"


server_socket.close()





























