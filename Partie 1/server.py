import socket
import os
import fcntl
import threading
import struct
import json
import pickle
import os.path
from os import path
import uuid
import subprocess
import glob

from threading import Thread
from SocketServer import ThreadingMixIn
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from Crypto import Random
import Crypto.Cipher.AES as AES
from Crypto.PublicKey import RSA

import datetime
from datetime import timedelta



###################### server ##############################


#################################################################################
#
#				Encrypt/Decrypt Message
#	
#
#################################################################################

## AES PassPhrass
cipher = AES.new('walidKHLOUF URCA')

def RemovePadding(s):
    return s.replace('`','')


def Padding(str):
	return str + ((16-len(str) % 16) * '{')
	
	
def encrypt_message(plaintext):
	global cipher
	return cipher.encrypt(Padding(plaintext))

def decrypt_message(ciphertext):
	global cipher
	dec = cipher.decrypt(ciphertext).decode('utf-8')
	l = dec.count('{')
	return dec[:len(dec)-l]



#################################################################################
#
#						Create ROOT CA
#	
#
#################################################################################




def create_CA():

	one_day = datetime.timedelta(1, 0, 0)

	try:
		private_key = rsa.generate_private_key(
			public_exponent=65537, key_size=2048, backend=default_backend()
		)
	except IOError:
    		print("Failed to generate the private key")
	

	try:
		public_key = private_key.public_key()
	except IOError:
    		print("Failed to generate the public key")
	
	try:
    		builder = x509.CertificateBuilder()

		builder = builder.subject_name(x509.Name([
		    		x509.NameAttribute(NameOID.COUNTRY_NAME, u'FR'),
				x509.NameAttribute(
					NameOID.STATE_OR_PROVINCE_NAME, u'Marne'), #Marne
				x509.NameAttribute(NameOID.LOCALITY_NAME, u'Reims'),
				x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Urca'),
				x509.NameAttribute(NameOID.COMMON_NAME, u'test.com'),
			]))

		builder = builder.issuer_name(x509.Name([
		    x509.NameAttribute(NameOID.COUNTRY_NAME, u'FR'),
		    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Marne'),
		    x509.NameAttribute(NameOID.LOCALITY_NAME, u'Reims'),
		    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Urca'),
		    x509.NameAttribute(NameOID.COMMON_NAME, u'test.com'),

		]))

		builder = builder.not_valid_before(datetime.datetime.today() - one_day )
		builder = builder.not_valid_after(datetime.datetime(2030, 8, 2))
		builder = builder.serial_number(int(uuid.uuid4()))
		builder = builder.public_key(public_key)
		builder = builder.add_extension(
		    x509.BasicConstraints(ca=True, path_length=None), critical=True,
		)


		certificate = builder.sign(private_key, hashes.SHA256(), default_backend())

		with open("cert/RootCA.pem", "wb") as certfile:

				certfile.write(certificate.public_bytes(serialization.Encoding.PEM))
					
					
		with open("private/RootCA.key", "wb") as keyfile:
			
			keyfile.write(private_key.private_bytes(
				
					encoding=serialization.Encoding.PEM,
					format=serialization.PrivateFormat.TraditionalOpenSSL,
					encryption_algorithm=serialization.BestAvailableEncryption(b"walidKH123456")
			))
   	except IOError:
    		print("Failed to generate the CSR certificate")
	

#################################################################################
#
#				Signe CSR
#	
#
#################################################################################

def signe_csr(csr):
	
	one_day = datetime.timedelta(1, 0, 0)

	
	#open csr client
	with open(csr,'rb') as f:
    		csr_data = x509.load_pem_x509_csr(f.read(),backend=default_backend())
		
	#open ROOT CA server
	with open('cert/RootCA.pem','rb') as f:
	   	CA_data = x509.load_pem_x509_certificate(f.read(), default_backend())
	
	
	#build csr with issuer CA data
	builder3 = x509.CertificateBuilder()
	builder3 = builder3.subject_name(csr_data.subject)
	builder3 = builder3.issuer_name(CA_data.issuer)
	builder3 = builder3.public_key(csr_data.public_key())
	builder3 = builder3.serial_number(int(uuid.uuid4()))
	builder3 = builder3.not_valid_before(datetime.datetime.today() - one_day)
	builder3 = builder3.not_valid_after(datetime.datetime(2022, 8, 2))

	# passphrase CA private key 
	passphrase = "walidKH123456"

	# open CA private key 
	with open('private/RootCA.key','rb') as private_key_file:
	    key = load_pem_private_key(private_key_file.read(),
	                               password=passphrase.encode(),
	                               backend=default_backend())

	# signe CSR client with CA Private key
	cert = builder3.sign(
	        private_key=key, algorithm=hashes.SHA256(),
	        backend=default_backend()
	    )
		
	# csr = "client_cert/key1.csr"
	csr_sub_name = csr[14:19]
	#Save CSR file
	with open("client_cert/certificate_client"+csr_sub_name+".pem", "wb") as certfile:
		certfile.write(cert.public_bytes(serialization.Encoding.PEM))




# objects
host = "10.10.0.1"
port = 40001

# check if directory exists if not create them

if os.path.isdir("client_csr"):
	pass
else:
	print("create directory client CSR ....") 
	os.mkdir("client_csr")

if os.path.isdir("client_cert"):
	pass
else:
	print("create directory client certifcate ....")
	os.mkdir("client_cert")

if os.path.isdir("cert"):
	pass
else:
	print("create directory Root CA ....")
	os.mkdir("cert")

if os.path.isdir("private"):
	pass
else:
	print("create directory PRIVATE ....")
	os.mkdir("private")


## CREATE RootCA in not exists
try:
        open("cert/RootCA.pem")
except:
        create_CA()


## clear directory

try:
	os.remove("client_cert/*")
except OSError:
	pass

try:
	os.remove("client_csr/*")
except OSError:
	pass



    
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((host, port))
server.listen(10)


client, address = server.accept()
print("\n\33[32m [X] client : %s is trying to connect... \33[0m") %(format(address))

#print "\33[32m \t\t\t\tSERVER WORKING \33[0m" 

	
client_data = client.recv(999999)

decrypted_data = decrypt_message(client_data)

json_dictionary = pickle.loads(decrypted_data)

print("\n\33[33m receive CSR from client %s \33[0m") %(format(address))

for key in json_dictionary:
	k = str(key)
	js = str(json_dictionary[key])
	with open('client_csr/'+key+'.csr', "w") as csrfile:
		csrfile.write(js)

#sign CSR 
list_of_CSR_files = glob.glob('client_csr/*.csr') 
for file_name in list_of_CSR_files:
	signe_csr(file_name)

print("\n\33[34m Sign CSR ..... \33[0m")


#Load client certif
data={}
list_of_cert_files = glob.glob('client_cert/*.pem') 
for file_name in list_of_cert_files:
	FI = open(file_name, 'r')
	#print file_name
	certif_sub_name = file_name[12:len(file_name)]
	data.update( {certif_sub_name: FI.read()} )
	
jsonData= pickle.dumps(data)

encrypted = encrypt_message(jsonData)	

#clientSocket.send(encrypted)


client.sendall(encrypted)

print("\n\33[34m send CSR Signed by CA ....\33[0m")

client.close()



























