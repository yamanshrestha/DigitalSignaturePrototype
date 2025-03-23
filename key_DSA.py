#importing modules
import os
import time
from Crypto.PublicKey import DSA
import sys

def loadingAnimationPrivate() : #function to create animation
    chars = ['/','—','-','\\','|']
    i = 0
    while i <= 30:
        time.sleep(0.1)
        sys.stdout.write("\r" + 'Generating Private Key ' + '.' + chars[i % len(chars)])
        sys.stdout.flush()
        i = i+1

def loadingAnimationPublic() :#function to create animation
    chars = "./—\|" 
    for i in range(50):
        time.sleep(0.1)
        sys.stdout.write("\r" + 'Generating Public Key ' + '.' + chars[i % len(chars)])
        sys.stdout.flush()


def generate(bitsize) : #creating funtion to generate keys
    key = DSA.generate(bitsize)
    loadingAnimationPrivate() #calling the function
    private_key = key.export_key() #storing private key
    #print ('\n')
    #print (private_key)
    time.sleep(1.3)
    print ('\n')
    loadingAnimationPublic() #calling animation function
    public_key = key.publickey().export_key() #storing public key
    #print ('\n')
    #print (public_key)
    current_dir = os.path.dirname(os.path.abspath(__file__))

    # Define the folder to store the keys
    key_folder = os.path.join(current_dir, "key")

    # Create the folder if it doesn't exist
    os.makedirs(key_folder, exist_ok=True)

    # Define the file paths for the keys
    private_key_path = os.path.join(key_folder, "PrivateKeyDSA.pem")
    public_key_path  = os.path.join(key_folder, "PublicKeyDSA.pem")

    # Write the private key
    with open(private_key_path, 'w') as f:
        f.write(private_key)

    # Write the public key
    with open(public_key_path, 'w') as f:
        f.write(public_key)
    return (private_key, public_key)
    print("Thank You! for Using Key Generation.")
    # f = open('/Users/' + os.getlogin() + '/Desktop'+ '/PrivateKeyDSA.pem', 'wb') #storing key file
    # f.write(private_key)
    # f.close()

    # f = open('/Users/' + os.getlogin() + '/Desktop' +'/PublicKeyDSA.pem','wb')
    # f.write(public_key)
    # f.close()
    # print("Thank You! for Using Key Generation")

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

    print("Thank You! for Using Key Generation")
    exit()