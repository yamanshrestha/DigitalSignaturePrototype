#importing modules
import os
import time
from Crypto.PublicKey import RSA
import sys

def loadingAnimationPrivate() : #function to show animation
    chars = ['/','—','-','\\','|']
    i = 0
    while i <= 30:
        time.sleep(0.1)
        sys.stdout.write("\r" + 'Generating Private Key ' + '.' + chars[i % len(chars)])
        sys.stdout.flush()
        i = i+1

def loadingAnimationPublic() :#function to show animation
    chars = ['/','—','-','\\','|']
    i = 0
    while i <= 30:
        time.sleep(0.1)
        sys.stdout.write("\r" + 'Generating Public Key ' + '.' + chars[i % len(chars)])
        sys.stdout.flush()
        i = i+1

def generate(bitsize) : #creating function that controls the key generation process
    key = RSA.generate(bitsize)
    loadingAnimationPrivate()
    private_key = key.exportKey('PEM') #storing privatekey into  private_key variable
    #print ('\n')
    #print (private_key)
    time.sleep(1.3)
    print ('\n')
    loadingAnimationPublic()
    pub_keygen = key.publickey() #storing public key into  public_keygen variable
    public_key = pub_keygen.exportKey('PEM')
    #print ('\n')
    #print (public_key)
    current_dir = os.path.dirname(os.path.abspath(__file__))

    # Define the folder to store the keys
    key_folder = os.path.join(current_dir, "key")

    # Create the folder if it doesn't exist
    os.makedirs(key_folder, exist_ok=True)

    # Define the file paths for the keys
    private_key_path = os.path.join(key_folder, "PrivateKeyRSA.pem")
    public_key_path  = os.path.join(key_folder, "PublicKeyRSA.pem")

    # Write the private key
    with open(private_key_path, 'wb') as f:
        f.write(private_key)

    # Write the public key
    with open(public_key_path, 'wb') as f:
        f.write(public_key)

    print("Thank You! Key Created Successfully.")
    return (private_key, public_key)

#Avoid same code execution in GUI 

if __name__ == "__main__":
    while True:
        try:
            bitsize = int(input("Enter the bit size of keys::"))
            if bitsize < 512:
                print ("The bitsize must be greater or equal to 512..")
                continue
            else:
                generate(bitsize)
                break
        except:
            print ("The given input is incorrect.")

    print("Thank You! Key Created Successfully")
    exit()  