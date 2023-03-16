
#FOR DSA
import os
import sys
from Crypto.PublicKey import DSA #importing Digital signature Algorithm module
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import base64

#function to generate signature and sign message
def generate_signature(key, data, signature_file):
    print("Generating Signature")
    h = SHA256.new(data)
    digest = h.hexdigest()
    print (digest)
    dsa = DSA.import_key(key)
    signer = DSS.new(dsa, 'fips-186-3')
    signature = signer.sign(h)
    encoding = base64.b64encode(signature)
    print (encoding)
    f = open('/Users/' + os.getlogin() +'/Desktop/' + signature_file, 'wb')
    f.write(encoding)
    f.close()

#function to verify signature and message.

def verify_signature(key, data, signature_file):
    print("Verifying Signature")
    f = open(signature_file, 'rb') #'/Users/'+ os.getlogin() +'/Desktop/' --excluded in GUI
    signature1 = f.read()
    signature = base64.b64decode(signature1)
    f.close()
    h = SHA256.new(data)
    dsa_publickey = DSA.importKey(key)
    verifier = DSS.new(dsa_publickey, 'fips-186-3')  

    try:
        verifier.verify(h, signature)
        print ("The document is successfully verified!!")
           
    except ValueError:
        print (" Verification Failure")
    
