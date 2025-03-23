
#For RSA Signature
#import modules
import os
import sys
from Crypto.PublicKey import RSA #import RSA module
from Crypto.Hash import SHA256 #import hash function
from Crypto.Signature import PKCS1_v1_5 #import signature standard for RSA
import base64 #for base64 encoding
import shutil

#function to generate signature
def generate_signature(key, data, file_path, signature_file): #generating signature
        print("Generating Signature")

        # 1) Hash the data
        h = SHA256.new(data)

        # 2) Import the private key
        rsa_key = RSA.importKey(key)
        signer = PKCS1_v1_5.new(rsa_key)

        # 3) Create the signature
        signature = signer.sign(h)
        # 4) Base64-encode it for easy storage
        encoded_signature = base64.b64encode(signature)

        # 5) Create the top-level "signature" folder
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
def verify_signature(key, data, signature_file):
    print("Verifying Signature")
    h = SHA256.new(data)
    rsa = RSA.importKey(key)
    signer = PKCS1_v1_5.new(rsa) 
    
    with open(signature_file, 'rb') as f:
        encoded_sig = f.read()

    # Decode from base64
    signature = base64.b64decode(encoded_sig)

    # Check signature
    if (signer.verify(h, signature)):
        return "The document is successfully verified!"
    else:
        return "Verification Failure"
