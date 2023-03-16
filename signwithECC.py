#import modules
import os
import sys
from Crypto.PublicKey import ECC #importing ECC module
from Crypto.Signature import DSS #importing Digital signature standard module
from Crypto.Hash import SHA256 #hash algorithm
import base64 #base64 encoding

#function to generate signature
def generate_signature(key, data, signature_file): #create function to generate signature
    print("Generating Signature")
    h = SHA256.new(data) #creating hash
    digest = h.hexdigest()
    print (digest)
    ecc = ECC.import_key(key) #loading the private key
    signer = DSS.new(ecc, 'fips-186-3')
    signature = signer.sign(h) #signing the hash
    encoding = base64.b64encode(signature) #encoding the generated signature
    print (encoding)
    f = open('/Users/' + os.getlogin() +'/Desktop/' + signature_file, 'wb')
    f.write(encoding) #saving signature file
    f.close()

#function to verify signature
def verify_signature(key, data, signature_file): #create function to verify signature
    print("Verifying Signature")
    f = open(signature_file, 'rb') #'/Users/'+ os.getlogin() +'/Desktop/'
    signature1 = f.read()
    signature = base64.b64decode(signature1) #decoding
    f.close()
    h = SHA256.new(data) #creating hash of document to verify
    ecc_publickey = ECC.import_key(key)#loading public key
    verifier = DSS.new(ecc_publickey, 'fips-186-3')  
    try:
        verifier.verify(h, signature)
        print ("The document is successfully verified!!")
    except:
        print (" Verification Failure")   