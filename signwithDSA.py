
#FOR DSA
import os
import sys
from Crypto.PublicKey import DSA #importing Digital signature Algorithm module
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import base64
import shutil

#function to generate signature and sign message
def generate_signature(key, data, file_path, signature_file):
    print("Generating Signature")
    h = SHA256.new(data)
    digest = h.hexdigest()
    print (digest)
    dsa = DSA.import_key(key)
    signer = DSS.new(dsa, 'fips-186-3')
    signature = signer.sign(h)
    encoded_signature= base64.b64encode(signature)
    
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
        return "The document is successfully verified!!"
           
    except ValueError:
        return "Verification Failure"
    
