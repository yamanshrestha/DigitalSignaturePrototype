#import modules
import os
import sys
from Crypto.PublicKey import ECC #importing ECC module
from Crypto.Signature import DSS #importing Digital signature standard module
from Crypto.Hash import SHA256 #hash algorithm
import base64 #base64 encoding
import shutil
#function to generate signature
def generate_signature(key, data, file_path, signature_file): #create function to generate signature
    print("Generating Signature")
    h = SHA256.new(data) #creating hash
    digest = h.hexdigest()
    print (digest)
    ecc = ECC.import_key(key) #loading the private key
    signer = DSS.new(ecc, 'fips-186-3')
    signature = signer.sign(h) #signing the hash
    encoded_signature = base64.b64encode(signature) #encoding the generated signature
    current_dir = os.path.dirname(os.path.abspath(__file__))
    signature_folder = os.path.join(current_dir, "signature")
    os.makedirs(signature_folder, exist_ok=True)

    # 6) Create a subfolder named after the signature_file (minus extension)
    subfolder_name, _ = os.path.splitext(signature_file)
    subfolder_path = os.path.join(signature_folder, subfolder_name)
    os.makedirs(subfolder_path, exist_ok=True)

    # 7) Write the signature file in the subfolder
    signature_path = os.path.join(subfolder_path, signature_file)
    with open(signature_path, 'wb') as f:
        f.write(encoded_signature)

    # 8) Also store the data you signed, in case you want it for reference
    original_filename = os.path.basename(file_path)
    data_dest_path = os.path.join(subfolder_path, original_filename)
    # Copy the original file into the subfolder
    shutil.copy(file_path, data_dest_path)

    print(f"Signature saved at: {signature_path}")
    print(f"Data file saved at: {data_dest_path}")
    print("Done.")

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
        return "The document is successfully verified!!"
    except:
        return "Verification Failure"  