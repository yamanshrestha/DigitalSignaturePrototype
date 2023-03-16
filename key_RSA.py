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
    print ('\n')
    print (private_key)
    time.sleep(1.3)
    print ('\n')
    loadingAnimationPublic()
    pub_keygen = key.publickey() #storing public key into  public_keygen variable
    public_key = pub_keygen.exportKey('PEM')
    print ('\n')
    print (public_key)
    f = open('c:/Users/' + os.getlogin() + '/Desktop'+ '/PrivateKeyRSA.pem', 'wb')
    f.write(private_key)
    f.close()

    f = open('c:/Users/' + os.getlogin() + '/Desktop' +'/PublicKeyRSA.pem','wb')
    f.write(public_key)
    f.close()
    print("Thank You! for Using Key Generation.")


#Avoid same code execution in GUI 

if __name__ == "__main__":
    while True:
        try:
            bitsize = int(input("Enter the bit size of keys::"))
            if bitsize < 1024:
                print ("The bitsize must be greater or equal to 1024..")
                continue
            else:
                generate(bitsize)
                break
        except:
            print ("The given input is incorrect.")

    print("Thank You! for Using Key Generation")
    exit()