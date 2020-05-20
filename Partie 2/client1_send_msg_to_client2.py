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
import subprocess
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




def sign_message(sock,message):

    data={}

    #message = "salut client 2 "
    

    #hash message
    prehashed = hashlib.sha256(message).hexdigest()


    #choose certificate and loaded
    list_of_CSR_files = glob.glob('cert/*.pem') 

    cert = random.choice(list_of_CSR_files)

    with open(cert,'rb') as f:
            #cert_data =  x509.load_pem_x509_certificate(f.read(), default_backend())
         cert_data =  f.read()

        #load private Key
        private_file = cert[23:28]

    # Read shared key from file
    with open ("private/private%s.key"%private_file, "r") as myfile:
            private_key = load_pem_private_key(myfile.read(), password="walidKH123456", backend=default_backend())

    #  Sign message with private Key
    sign_msg = private_key.sign(
            prehashed,
            padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())

    print("\n\33[32m message successfully signed \33[0m")


    #create dict
    
    data.update( {"message": message, "Signature": base64.b64encode(sign_msg), "cetificate" :  str(cert_data)} )
    #base64.b64encode(sign_msg)
    jsonData= pickle.dumps(data)

    

    encrypted = encrypt_message(jsonData)

    #sock.send(encrypted)
    #sleep(10)

    return encrypted 




def main():

    host = '10.10.0.3'
    port = 5001

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    
    # connecting host
    try :
        s.connect((host, port))
    except :
        print "\33[31m\33[1m Can't connect to the server \33[0m"
        sys.exit()

  
    data = sign_message(s,"salut client 2")
    s.send(data)
    print("\n\33[33m message sended successfully \33[0m")


    

if __name__ == "__main__":
    main()