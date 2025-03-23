
import os
from Crypto.PublicKey import ElGamal
from Crypto.Util import number
from Crypto import Random
import sys, time
import base64
def loadingAnimationPrivate() :
    chars = ['/','—','-','\\','|']
    i = 0
    while i <= 30:
        time.sleep(0.1)
        sys.stdout.write("\r" + 'Generating Private Key ' + '.' + chars[i % len(chars)])
        sys.stdout.flush()
        i = i+1

def loadingAnimationPublic() :
    chars = ['/','—','-','\\','|']
    i = 0
    while i <= 30:
        time.sleep(0.1)
        sys.stdout.write("\r" + 'Generating Public Key ' + '.' + chars[i % len(chars)])
        sys.stdout.flush()
        i = i+1

def generate(bitsize) :
    #bitsize = int(input("Enter the bit size of keys::"))
    key = ElGamal.generate(bitsize, randfunc=Random.get_random_bytes)
    loadingAnimationPrivate()
    private_keyx = key.x
    #print ('\n')
    #print (private_key)
    time.sleep(1.3)
    print ('\n')
    loadingAnimationPublic()
    public_keyy = key.y
    #print ('\n')
    #print (public_key)
    # It is advisable to also store the key parameters p and g
    p = key.p
    g = key.g

    current_dir = os.path.dirname(os.path.abspath(__file__))

    # Define the folder to store the keys
    key_folder = os.path.join(current_dir, "key")

    # Create the folder if it doesn't exist
    os.makedirs(key_folder, exist_ok=True)

    # Define the file paths for the keys
    private_key_path = os.path.join(key_folder, "PrivateKeyElgalmal.txt")
    public_key_path  = os.path.join(key_folder, "PublicKeyElgalmal.txt")

    private_key = (
        "p: " + str(p) + "\n" +
        "g: " + str(g) + "\n" +
        "x (private exponent): " + str(private_keyx) + "\n"
    )
    
    # For the public key, include p, g, and y.
    public_key = (
        "p: " + str(p) + "\n" +
        "g: " + str(g) + "\n" +
        "y (public component): " + str(public_keyy) + "\n"
    )
    
    # Write the private key
    with open(private_key_path, 'w') as f:
        f.write(private_key)

    # Write the public key
    with open(public_key_path, 'w') as f:
        f.write(public_key)

    print("Thank You! for Using Key Generation.")
    return (private_key, public_key)

#Avoid same code execution in GUI 

if __name__ == "__main__":
    while True:
        try:
            bitsize = int(input("Enter the bit size of keys::"))
            if bitsize < 256:
                print ("The bitsize must be greater or equal to 256..")
                continue
            else:
                generate(bitsize)
                break
        except:
            print ("The given input is incorrect.")

    print("Thank You! for Using Key Generation")
    exit()