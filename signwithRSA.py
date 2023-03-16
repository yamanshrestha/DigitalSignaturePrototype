
#For RSA Signature
#import modules
import os
import sys
from Crypto.PublicKey import RSA #import RSA module
from Crypto.Hash import SHA256 #import hash function
from Crypto.Signature import PKCS1_v1_5 #import signature standard for RSA
import base64 #for base64 encoding

#function to generate signature
def generate_signature(key, data, signature_file): #generating signature
    print("Generating Signature")
    h = SHA256.new(data) #generate hash
    rsa = RSA.importKey(key)
    signer = PKCS1_v1_5.new(rsa)
    signature = signer.sign(h)
    encoding = base64.b64encode(signature) #encoding signature
    print (encoding)
    f = open('C:/Users/' + os.getlogin() +'/Desktop/' + signature_file, 'wb')
    f.write(encoding)
    f.close()

#function to verify signature
def verify_signature(key, data, signature_file):
    print("Verifying Signature")
    h = SHA256.new(data)
    rsa = RSA.importKey(key)
    signer = PKCS1_v1_5.new(rsa) 
    
    
    f = open(signature_file, 'rb') # '/Users/'+ os.getlogin() +'/Desktop/' + opening signature file --excluded in GUI 
    signature1 = f.read()
    signature = base64.b64decode(signature1) #decoing file
    f.close()
    if (signer.verify(h, signature)) == True:
        print ("The document is successfully verified!!")
           
    else:
        print (" Verification Failure")
