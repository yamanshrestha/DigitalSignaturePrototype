#importing modules
import os
import time
from Crypto.PublicKey import ECC
import sys

def loadingAnimationPrivate() : #function to create animation
    chars = ['/','—','-','\\','|']
    i = 0
    while i <= 30:
        time.sleep(0.1)
        sys.stdout.write("\r" + 'Generating Private Key ' + '.' + chars[i % len(chars)])
        sys.stdout.flush()
        i = i+1

def loadingAnimationPublic() : #function to create animation
    chars = ['/','—','-','\\','|']
    i = 0
    while i <= 30:
        time.sleep(0.1)
        sys.stdout.write("\r" + 'Generating Public Key ' + '.' + chars[i % len(chars)])
        sys.stdout.flush()
        i = i+1

def generate(usecurve) :  #generating keys
    key = ECC.generate(curve= usecurve) #use secp256r1 for testing
    loadingAnimationPrivate()
    private_key = key.export_key(format="PEM") #storing private key
    #print ('\n')
    #print (private_key)
    time.sleep(1.3)
    print ('\n')
    loadingAnimationPublic()
    public_key = key.public_key().export_key(format="PEM") #storing public key to variable
    #print ('\n')
    #print (public_key)
#saving generated keys
    current_dir = os.path.dirname(os.path.abspath(__file__))

    # Define the folder to store the keys
    key_folder = os.path.join(current_dir, "key")

    # Create the folder if it doesn't exist
    os.makedirs(key_folder, exist_ok=True)

    # Define the file paths for the keys
    private_key_path = os.path.join(key_folder, "PrivateKeyECC.pem")
    public_key_path  = os.path.join(key_folder, "PublicKeyECC.pem")

    # Write the private key
    with open(private_key_path, 'wb') as f:
        f.write(private_key.encode('utf-8'))

    # Write the public key
    with open(public_key_path, 'wb') as f:
        f.write(public_key.encode('utf-8'))

    print("Thank You! Key Created Successfully.")
    
    return (private_key, public_key)

    # f = open('c:/Users/' + os.getlogin() + '/Desktop'+ '/PrivateKeyECC.pem', 'w')
    # f.write(private_key)
    # f.close()

    # f = open('c:/Users/' + os.getlogin() + '/Desktop' +'/PublicKeyECC.pem','w')
    # f.write(public_keygen)
    # f.close()


#to avoid this code execution in main GUI
if __name__ == "__main__":
    #list of curves
    p_names = ["p256", "NIST P-256", "P-256", "prime256v1", "secp256r1",
                "nistp256", "p384", "NIST P-384", "P-384", "prime384v1",
                "secp384r1", "nistp384", "p521", "NIST P-521", "P-521",
                "prime521v1", "secp521r1","nistp521"]
    while True:
        print (p_names)
        c_name = input("Enter the curve name, eg secp256r1::")
        if c_name in p_names:
            generate(c_name)
            break
        else:
            print ("The curve must be selected from above list.")
            continue
        print("Thank You! Key Created Successfully")
        exit()