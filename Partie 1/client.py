import socket
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
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


####################  client ######################

HOST = '10.10.0.1'
PORT = 40001
FLAG_READY = "Ready"
FLAG_QUIT = "quit"
BUFFER_SIZE = 2024


## AES PassPhrass
cipher = AES.new('walidKHLOUF URCA')



def RemovePadding(s):
    return s.replace('`','')

##  to crypte long text
def Padding(str):
	return str + ((16-len(str) % 16) * '{')



#################################################################################
#
#				Encrypt/Decrypt Message
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
	
#################################################################################
#
#				Create Client CSR
#	
#
#################################################################################
	
def create_CSR(j):
	try:
		
		## CREATE PRIVATE KEY RSA
		private_key_client = rsa.generate_private_key(
			public_exponent=65537, key_size=2048, backend=default_backend()
			)

		## GENERATE PUBLIC KEY
		public_key_client = private_key_client.public_key()

		
		## INFO ABOUT CERTIFICATE CSR
		C = raw_input("Country Name (2 letter code) [FR]:") or "FR"

		ST = raw_input("State or Province Name (full name) [Grand-EST]:") or "Grand-EST"

		L = raw_input("Locality Name (eg, city) []:") or "Reims"

		O = raw_input("Organization Name (eg, company) [M1-DAS URCA]:") or "M1-DAS URCA"

		CN = raw_input("Common Name (eg, YOUR name) []") or socket.gethostname()+".fr"


		## BUILD INFO 
		builder = x509.CertificateSigningRequestBuilder()
		builder = builder.subject_name(x509.Name([
				x509.NameAttribute(NameOID.COUNTRY_NAME,u''+C),
				x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,u''+ST),
      				x509.NameAttribute(NameOID.LOCALITY_NAME,u''+L),
      				x509.NameAttribute(NameOID.ORGANIZATION_NAME,u''+O),
     				x509.NameAttribute(NameOID.COMMON_NAME,u''+CN),
			]))

		builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True,)


		## SIGN CSR
		CSR = builder.sign(private_key_client, hashes.SHA256(), default_backend())

		## SAVE CSR IN FILE
		
		with open('CSR_file/csr_key%s.csr' %j, "w") as certfile:

			certfile.write(CSR.public_bytes(serialization.Encoding.PEM))

		
		print("private/private_key%s.key" %j)
		try:
			with open("private/private_key%s.key" %str(j), "wb") as keyfile:
			
				keyfile.write(private_key_client.private_bytes(
				
					encoding=serialization.Encoding.PEM,
					format=serialization.PrivateFormat.TraditionalOpenSSL,
					encryption_algorithm=serialization.BestAvailableEncryption(b"walidKH123456")
				))
		except IOError:
			print("Error to create private Key !")
	except IOError:
		print("Error to create Certificate !")
		
	#return CSR.public_bytes(serialization.Encoding.PEM)


#################################################################################
#
#				Main
#	
#
#################################################################################


# check if directory exists if not create them

if os.path.isdir("CSR_file"):
	pass
else:
	print("create directory CSR ....") 
	os.mkdir("CSR_file")

if os.path.isdir("cert"):
	pass
else:
	print("create directory client certifcate ....")
	os.mkdir("cert")

if os.path.isdir("private"):
	pass
else:
	print("create directory client certifcate ....")
	os.mkdir("private")


## clear directory

try:
	os.remove("cert/*")
	print("clear cert directory ....")
except OSError:
	pass

try:
	os.remove("CSR_file/*")
	print("clear CSR directory ....")
except OSError:
	pass

try:
	os.remove("private/*")
	print("clear private directory ....")
except OSError:
	pass




server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.settimeout(10)
server.connect((HOST, PORT))
	
data={}
pool = int(raw_input("\n\33[34m Enter the pool number : \33[0m") or 1)
		
#dirName = create_dir()
#os.mkdir(dirName)

for j in range(int(pool)):
	print('\nCreate CSR Num : '+str(j+1)+'\n')
	create_CSR(int(j+1))
	with open('CSR_file/csr_key%s.csr' %str(j+1),'rb') as f:
		data.update( {'csr_key%s'%str(j+1): f.read()} )
		
jsonData= pickle.dumps(data)
	
encrypted = encrypt_message(jsonData)
	
## SEND ENCRYPTED MESSAGE
server.send(encrypted)

print("\n \33[33m Send CSR to the SERVER .... \33[0m")

sleep(1)

data_recev = server.recv(999999)


decrypted_data = decrypt_message(data_recev)

json_dictionary = pickle.loads(decrypted_data)

print("\n\33[33m receive CSR Signed by CA ...... \33[0m")


for key in json_dictionary:
	k = str(key)
	js = str(json_dictionary[key])
	#csr_sub_name = key[12:len(key)]
	with open('cert/'+key, "w") as csrfile:
		csrfile.write(js)



server.close()



	