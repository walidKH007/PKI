import socket, select, string, sys
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

##  to crypte long text
def Padding(str):
    return str + ((16-len(str) % 16) * '{')



#################################################################################
#
#               Encrypt/Decrypt Message
#   
#
#################################################################################

    
    
def encrypt_message(plaintext):
    global cipher
    return cipher.encrypt(Padding(plaintext))

def decrypt_message(ciphertext):
    global cipher
    dec = cipher.decrypt(ciphertext)
    l = dec.count('{')
    return dec[:len(dec)-l]



host = '10.10.0.1'
port = 5001

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(10)
   
# connecting host
try :
	s.connect((host, port))
except :
	print "\33[31m\33[1m Can't connect to the server \33[0m"
	sys.exit()

with open("cetificate.pem",'rb') as f:
	     cert_data =  f.read()


data={}
data.update( {"cetificate" :  cert_data} )

jsonData= pickle.dumps(data)

s.send(encrypt_message(jsonData))


print "\33[32m certificate successfully sent  \33[0m"


sleep(1)

msg=s.recv(99999)

decrypted_data = decrypt_message(msg)

if decrypted_data == 'valid':
	print "\n\33[32m valid certificat \33[0m"
else:
	print "\n\33[32m invalid certificat  \33[0m"



s.close()


    

