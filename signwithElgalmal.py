
#For Elgalmal Signature

import os
import sys
from Crypto.PublicKey import ElGamal
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
import base64

def usage():
    print("Usage: \n"
            "mainsign -s  <private_key> <data to be sign> <signature-file> \n"
            "mainsign -v  <PUB-key> <data to be verify> <signature-file> \n")

if (len(sys.argv) < 5):
    usage()
    quit()

int_check = sys.argv[1]
key_file = sys.argv[2]
data_file = sys.argv[3]
signature_file = sys.argv[4]

def generate_signature(key, data, signature_file):
    print("Generating Signature")
    h = SHA256.new(data)
    #print (h.hexdigest())
    #h1 = h.digest_size()
    elgalmal = ElGamal.construct(key)
    signer = PKCS1_v1_5.new(elgalmal)
    signature = signer.sign(h)
    encoding = base64.b64encode(signature)
    print (encoding)
    f = open(r'C:/Users/' + os.getlogin() +'/Desktop/' + signature_file, 'wb')
    f.write(encoding)
    f.close()

def verify_signature(key, data, signature_file):
    print("Verifying Signature")
    h = SHA256.new(data)
    elgalmal = ElGamal.construct(key)
    signer = PKCS1_v1_5.new(elgalmal)
    
    
    f = open('/Users/'+ os.getlogin() +'/Desktop/' + signature_file, 'rb')
    signature1 = f.read()
    signature = base64.b64decode(signature1)
    f.close()
    if (signer.verify(h, signature)) == True:
        print ("The document is successfully verified!!")
           
    else:
        print (" Verification Failure")

#if __name__ == '__main__':
    # Read all file contents
f = open(key_file, 'rb')
key = f.read()
f.close()

f = open(data_file, 'rb')
data = f.read()
f.close()

if (int_check == "-s"):
    # Generate Signature
    generate_signature(key, data, signature_file)
elif (int_check == "-v"):
    # Verify Signature
    verify_signature(key, data, signature_file)
else:
    #Error
    usage()
