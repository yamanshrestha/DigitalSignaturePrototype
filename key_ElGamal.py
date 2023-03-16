
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
    private_key = key.x
    print ('\n')
    print (private_key)
    time.sleep(1.3)
    print ('\n')
    loadingAnimationPublic()
    public_key = key.y
    print ('\n')
    print (public_key)
    
    f = open('/Users/' + os.getlogin() + '/Desktop'+ '/PrivateKeyElgalmal.pem', 'w')
    f.write(str(private_key))
    f.close()

    f = open('/Users/' + os.getlogin() + '/Desktop' +'/PublicKeyElgalmal.pem','w')
    f.write(str(public_key))
    f.close()
    print("Thank You! for Using Key Generation")

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