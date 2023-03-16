#Importing the modules
from tkinter import *
from tkinter import ttk
#from tkinter import Menu
from tkinter import filedialog

from tkinter import messagebox
import key_RSA #importing file to generate RSA key: **Every key pair generated is of for single person
import key_DSA #importing file to generate DSA key: **Every key pair generated is of for single person
import key_ECC #importing file to generate ECC key: **Every key pair generated is of for single person
import key_ElGamal #importing file to generate Elgalmal key: **Every key pair generated is of for single person
import signwithRSA  #importing file to create and verify signature using RSA
import signwithDSA #importing file to create and verify signature using DSA
#import signwithElgalmal #importing file to create and verify signature using elgalmal
import signwithECC #importing file to create and verify signature using ECC
import sys
import os


class Generate(ttk.Frame): #Creating class that connects every file to generate keys.
    def __init__(self, parent): 
        ttk.Frame.__init__(self, parent)
        def labelframe_calg(): #creating label frame that contains information about the type of key to generate
            labelframe_calg = LabelFrame(frame1, height = 90, width = 470, text = 'Choose Algorithm').pack()
            choose_calg = Label(frame1, text="Choose the type of key you want to generate")
            choose_calg.place(x = 5 , y = 15)
        labelframe_calg()
        def checklist():
            global bits #making global variable to access outside of this function and class
            global algorithm
            global curve
            global curve_choose   
            curve = StringVar() 
            bits = IntVar()
            bits.set(1024)
            bitsize_label = Label(frame1, text = "Bit Size").place(x = 250, y = 61)
            curve_label = Label(frame1, text = "Curve").place(x = 250, y = 35)
            bitsize_entry = Entry(frame1, textvariable = bits ,width = 23).place(x = 310, y = 61.5)
            #Creating algorithm options
            algorithm = IntVar()

            radio_rsa = Radiobutton(frame1, text = 'RSA', variable = algorithm , value = 1) #creating RSA radiobutton
            radio_rsa.place(x = 20, y = 33)

            radio_ecc = Radiobutton(frame1, text = 'DSA', variable = algorithm, value = 2) #creating ECC radiobutton
            radio_ecc.place(x = 100, y = 33)

            radio_dsa = Radiobutton(frame1, text = 'ECC', variable = algorithm, value = 3) #creating DSA radiobutton
            radio_dsa.place(x = 180, y = 33)

            radio_elgalmal = Radiobutton(frame1, text = 'ELGalmal', variable = algorithm, value = 4) #creating elgalmal radiobutton
            radio_elgalmal.place(x = 20, y = 60)
            
            curve_choose = ttk.Combobox(frame1, width = 20, textvariable = curve) #this combobox allows user to select the specific curve
            curve_choose.place(x = 310, y = 30)
            

            curve_choose['values'] = ("p256", "NIST P-256", "P-256", "prime256v1", "secp256r1", "nistp256",
                            "p384", "NIST P-384", "P-384", "prime384v1", "secp384r1", "nistp384",
                            "p521", "NIST P-521", "P-521", "prime521v1", "secp521r1","nistp521")
            curve_choose.current(4)
            #curve_choose['state'] = 'disabled'

        checklist()

        def ecc_curve():
            if algorithm.get() == 3:
                ecckey = StringVar()
                ecckey = key_ECC.generate(curve.get()) #when ECC is selected to generate keys; it calls that paticular module
                messagebox.showinfo("Complete", "ECC Keypair successfully created!")
            else: 
                select()
      
        def select(): #this function checks what algorithm is selected, selected bitsize, calls the specified modules
            try:
                if bits.get() >= 1024:
                    if algorithm.get()==1:
                        #global mykey
                        rsakey = StringVar()
                        rsakey = key_RSA.generate(bits.get()) #when RSA is selected to generate keys; it calls that paticular module
                        messagebox.showinfo("Complete", "RSA Keypair successfully created!")
                    elif algorithm.get()==2:
                        dsakey = StringVar()
                        dsakey = key_DSA.generate(bits.get()) #when DSA is selected to generate keys; it calls that paticular module
                        messagebox.showinfo("Complete", "DSA Keypair successfully created!")

                    elif algorithm.get()==4:
                        elgalmalkey = StringVar()
                        elgalmalkey = key_ElGamal.generate(bits.get()) #when Elgalmal is selected to generate keys; it calls that paticular module
                        messagebox.showinfo("Complete", "Elgalmal Keypair successfully created!")
                    else:
                        messagebox.showerror("ERROR", " No Parameters Found.")
                else:
                    messagebox.showerror("ERROR", " The bitsize must be >= 1024") #gives error if bitsize is less than 1024
            except:
                messagebox.showerror("ERROR", " The given bitsize is not valid.")

        def labelframe_direct(): #creating label frame that contains information about direction; generate keys view keys
            
            labelframe_direct = LabelFrame(frame1, height = 90, width = 470, text = 'Direction').pack()
            genetate_key = Label(frame1, text="Generate Public/Private Key")
            load_key = Label(frame1, text="Load Existing Key")
            genetate_key.place(x = 5 , y = 110)
            load_key.place(x = 5, y = 135)
            
            btn_generate_key = Button(frame1, text = 'Generate Key', command = lambda: ecc_curve()) #creating button widget to generate keys using selected algorithm and calls select function
            btn_generate_key.place(x = 365, y = 103, width = 91) 
            #Creating Button widget to load key
            btn_load_privatekey = Button(frame1, text = 'Load Public Key', command = lambda : open_publickey())  #creating button widget to load public key and calls specified function
            btn_load_privatekey.place(x = 365, y = 135, width = 91)
            btn_load_publickey = Button(frame1, text = 'Load Private Key', command = lambda : open_privatekey())  #creating button widget to load private key and calls specified function
            btn_load_publickey.place(x = 270, y = 135, width = 91) 
            
        labelframe_direct()
        def open_privatekey(): #creating function to open private key and display
            try:
                op_prvkey = filedialog.askopenfilename(initialdir ="Desktop", title = "Open File", filetypes =(("Key File", "*.PEM"),("Text Files", "*.txt") ) ) 
                op_prvkey_contain = open(op_prvkey, 'r')
                private_f = op_prvkey_contain.read()
                private_keyout.delete('1.0',END)
                private_keyout.insert(INSERT, private_f)
                private_keyout.configure(state = 'disabled')
                op_prvkey_contain.close()
            except:
                messagebox.showerror("ERROR","No private key selected.")
        def open_publickey(): #creating function to open private key and display
            try:
                op_pubkey = filedialog.askopenfilename(initialdir ="Desktop", title = "Open File", filetypes = (("Key File", "*.PEM"),("Text Files", "*.txt") ) ) 
                op_pubkey_contain = open(op_pubkey, 'r')
                public_f = op_pubkey_contain.read()
                public_keyout.delete('1.0', END)
                public_keyout.insert(INSERT, public_f)
                public_keyout.configure(state = 'disabled')
                op_pubkey_contain.close()
            except:
                messagebox.showerror("ERROR","No public key selected.")

        def labelframe_key(): #creating label frame that contains information about viewing keys
            global public_keyout
            global private_keyout
            public_keyout = StringVar()
            private_keyout = StringVar()
            labelframe_key = LabelFrame(frame1, height = 260, width = 470, text = 'Key').pack()
            private_key_label = Label(frame1, text = "Private Key").place(x = 10, y = 200)
            private_keyout = Text(frame1,width = 28, height = 13)
            private_keyout.insert(END, " No Key Selected")
            private_keyout.place(x = 5, y = 225)
            public_key_label = Label(frame1, text = "Public Key").place(x = 260, y = 200)
            public_keyout = Text(frame1,width = 28, height = 13)
            public_keyout.place(x = 240, y = 225)
            public_keyout.insert(END, " No Key Selected")
            #return private_key, public_key
        labelframe_key()
#==========SIGN==========================================================================
class Sign(ttk.Frame):
    def __init__(self, parent):
        ttk.Frame.__init__(self, parent)
        def intro(): #this function shows how the required information for sigining
            messagebox.showinfo("DISCLAIMER", "The following syntax is followed to sign and verify: \n"
                "<signing_algorithm> -s  <private_key> <data to be signed> <signature-file> \n"
                "<same_algorithm> -v  <PUB-key> <data to be verified> <signature-file> \n")

        def labelframe_calg(): #label that shows the algorithm information 
            global algorithm_1
            labelframe_calg = LabelFrame(frame2, height = 90, width = 470, text = 'Choose Algorithm').pack()
            choose_calg = Label(frame2, text="Choose the type of key to sign Document.")
            choose_calg.place(x = 5 , y = 15)
            #Creating algorithm options
            algorithm_1 = IntVar()
            radio_rsa = Radiobutton(frame2, text = 'RSA', variable = algorithm_1 , value = 1) #creating RSA radiobutton
            radio_rsa.place(x = 20, y = 33)

            radio_ecc = Radiobutton(frame2, text = 'DSA', variable = algorithm_1, value = 2) #creating ECC radiobutton
            radio_ecc.place(x = 100, y = 33)

            radio_dsa = Radiobutton(frame2, text = 'ECC', variable = algorithm_1, value = 3) #creating DSA radiobutton
            radio_dsa.place(x = 180, y = 33)
            btn_info = Button(frame2, text = 'View INFO', command = lambda: intro())
            btn_info.place(x = 360, y = 30, width = 91)
        labelframe_calg()
        def datatosign(): #ask and reads input of file to be signed
            try:
                global data_file
                file_name3 = filedialog.askopenfilename(initialdir ="Desktop", title = "Open File", filetypes = (("All Files", "*.*"),("Key File", "*.PEM")) ) 
                f3 = open(file_name3, 'rb')
                data_file = f3.read()
                file_dir.configure(state = 'normal')
                file_dir.delete('0', END)
                file_dir.insert(END, file_name3)
                file_dir.configure(state = 'disabled')
                messagebox.showinfo("Data File", "Sigining file is successfully added")
                f3.close()
            except:
                messagebox.showerror("ERROR","No file selected.")
        def labelframe_direct(): #this function looks ater choosing file and signature file name
        
            global dest_name
            global file_dir
            dest_name = StringVar()
            labelframe_direct = LabelFrame(frame2, height = 90, width = 470, text = 'Direction').pack()
            label_choosefile = Label(frame2, text="Choose the File you wish to sign.") #
            label_choosesignfile = Label(frame2, text="Give the filename for your signature") #
            file_dir = Entry(frame2)
            file_dir.place(x = 205, y= 110, width = 230)
            label_choosefile.place(x = 5 , y = 110)
            label_choosesignfile.place(x = 5, y = 135)            
            #Creating Button widget to load key
            btn_choose_key = Button(frame2, text = '...', command = lambda: datatosign())
            btn_choose_key.place(x = 438, y = 105, width = 20)
            get_destname = Entry(frame2, textvariable = dest_name)
            get_destname.place(x = 205, y = 135, width = 230)
            #sign_dest = dest_name.get()
        labelframe_direct()

        def labelframe_key(): # this function creates the frame that contains signing button, adding private key
            public_keysign = StringVar()
            private_keysign = StringVar()
            labelframe_key = LabelFrame(frame2, height = 260, width = 470, text = 'Key').pack()
            private_key_label = Label(frame2, text = "Select Private to sign & Public to verify")
            private_key_label.place(x = 5, y = 200)
            public_key_label = Label(frame2, text = "Select Sign/verify accordingly")
            public_key_label.place(x = 5, y = 235)
            
            btn_public_key = Button(frame2, text = 'PublicKey', state = DISABLED , command = lambda: open_publickey())
            btn_public_key.place(x = 380, y = 200, width = 91) 
            #Creating Button widget to load key

            btn_private_key = Button(frame2, text = 'Private Key', command = lambda : open_privatekey())  
            btn_private_key.place(x = 270, y = 200, width = 91) #x = 270, y = 135, width = 91

            btn_sign = Button(frame2, text = 'Sign', command = lambda : sign_select())  
            btn_sign.place(x = 270, y = 235, width = 91) #x = 270, y = 135, width = 91

            btn_verify = Button(frame2, text = 'Verify', state = DISABLED ,command = lambda : verify_select())  
            btn_verify.place(x = 380, y = 235, width = 91)

        labelframe_key()
        def open_privatekey(): #function to open key file
            try:
                global private_s
                file_name1 = filedialog.askopenfilename(initialdir ="Desktop", title = "Open File", filetypes =(("Key File", "*.PEM"),("Text Files", "*.txt") ) ) 
                f1 = open(file_name1, 'rb')
                private_s = f1.read()
                messagebox.showinfo("Private Key", "Private key added successfully!")
                f1.close()
            except:
                messagebox.showerror("ERROR","No private key selected.")
        def sign_select():
            if algorithm_1.get()==1:
                sign_key = StringVar()
                sign_key = signwithRSA.generate_signature(private_s,data_file, dest_name.get())
                messagebox.showinfo("Complete", "RSA Signature successfully created!")
            elif algorithm_1.get()==2:
                sign_key = signwithDSA.generate_signature(private_s,data_file, dest_name.get())
                messagebox.showinfo("Complete", "DSA Signature successfully created!")
            elif algorithm_1.get()==3:
                sign_key = signwithECC.generate_signature(private_s,data_file, dest_name.get())
                messagebox.showinfo("Complete", "ECC Signature successfully created!")
            else:
                messagebox.showerror("ERROR", " Incorrect Parameters. Check the key file or algorithm")
        

#=========Verify=========================================================================
class Verify(ttk.Frame):
    def __init__(self, parent):
        ttk.Frame.__init__(self, parent)
        def intro():
            messagebox.showinfo("DISCLAIMER", "The following syntax is followed to sign and verify: \n"
                "<signing_algorithm> -s  <private_key> <data to be signed> <signature-file> \n"
                "<same_algorithm> -v  <PUB-key> <data to be verified> <signature-file> \n")

        def choose_algorithm(): #This section contains the selection of algorithm to verify signature.
            choose_algorithm = LabelFrame(frame3, height = 90, width = 470, text = 'Choose Algorithm').pack()
            choose_calg = Label(frame3, text="Choose the type of key to verify Document.")
            choose_calg.place(x = 5 , y = 15)
            
            #Creating algorithm options
            global algorithm_2
            algorithm_2 = IntVar()
            #creating RSA radiobutton
            radio_rsa = Radiobutton(frame3, text = 'RSA', variable = algorithm_2 , value = 1)
            radio_rsa.place(x = 20, y = 33)
            #creating DSA radiobutton
            radio_dsa = Radiobutton(frame3, text = 'DSA', variable = algorithm_2, value = 2)
            radio_dsa.place(x = 100, y = 33)
            #creating ECC radiobutton
            radio_ecc = Radiobutton(frame3, text = 'ECC', variable = algorithm_2, value = 3)
            radio_ecc.place(x = 180, y = 33)
            #This button views the process to verify Document.
            btn_info = Button(frame3, text = 'View INFO', command = lambda: intro())
            btn_info.place(x = 360, y = 30, width = 91)
        choose_algorithm()

        def Direction():
            global choosekey_dir
            global signaturekey_dir
            dest_name = StringVar()
            labelframe_direct = LabelFrame(frame3, height = 90, width = 470, text = 'Direction').pack()
            generate_key = Label(frame3, text="Choose the File you want to verify.") #
            load_key = Label(frame3, text="Choose the file containing signature") #
            generate_key.place(x = 5 , y = 110)
            load_key.place(x = 5, y = 135)

            
            #Creating Button widget to load key
            btn_choose_key = Button(frame3, text = '...', command = lambda: datatoverify())
            btn_choose_key.place(x = 433, y = 107, width = 20)
            choosekey_dir = Entry(frame3)
            choosekey_dir.place(x = 200, y= 110, width = 230)

            select_signaturefile = Button(frame3, text = '...', command = lambda: signature_file())
            select_signaturefile.place(x = 433, y = 134, width = 20)
            signaturekey_dir = Entry(frame3)
            signaturekey_dir.place(x = 200, y= 135, width = 230)


        Direction()
        def Verify_process():
            labelframe_key = LabelFrame(frame3, height = 260, width = 470, text = 'Key').pack()
            private_key_label = Label(frame3, text = "Select Private to sign & Public to verify")
            private_key_label.place(x = 5, y = 200)
            public_key_label = Label(frame3, text = "Select Sign/verify accordingly")
            public_key_label.place(x = 5, y = 235)
            
            btn_public_key = Button(frame3, text = 'PublicKey', command = lambda: open_publickey())
            btn_public_key.place(x = 380, y = 200, width = 91) 
            #Creating Button widget to load key

            btn_private_key = Button(frame3, text = 'Private Key', state = DISABLED)  
            btn_private_key.place(x = 270, y = 200, width = 91) #x = 270, y = 135, width = 91

            btn_sign = Button(frame3, text = 'Sign', state = DISABLED,command = lambda : sign_select())  
            btn_sign.place(x = 270, y = 235, width = 91) #x = 270, y = 135, width = 91

            btn_verify = Button(frame3, text = 'Verify', command = lambda : verify_select())  
            btn_verify.place(x = 380, y = 235, width = 91)

        Verify_process()

        def datatoverify(): #This section contains the Files to verify signature.
            try:
                global data_filev # read the file to verify
                file_name4 = filedialog.askopenfilename(initialdir ="Desktop", title = "Open File", filetypes = (("All Files", "*.*"),("Key File", "*.PEM")) ) 
                f4 = open(file_name4, 'rb')
                data_filev = f4.read()
                choosekey_dir.configure(state = 'normal')
                choosekey_dir.delete('0', END)
                choosekey_dir.insert(END, file_name4)
                choosekey_dir.configure(state = 'disabled')
                messagebox.showinfo("Data File", "Sigining file is successfully added")
                f4.close()
            except:
                messagebox.showerror("ERROR", "No file selected.")
        
        def signature_file(): #This section contains the Files to verify signature.
            try:
                global signature_details # read the file to verify
                global file_name5
                file_name5 = filedialog.askopenfilename(initialdir ="Desktop", title = "Open File", filetypes = (("All Files", "*.*"),("Key File", "*.txt")) ) 
                f5 = open(file_name5, 'rb')
                signature_details = f5.read()
                signaturekey_dir.configure(state = 'normal')
                signaturekey_dir.delete('0', END)
                signaturekey_dir.insert(END, file_name5)
                signaturekey_dir.configure(state = 'disabled')
                messagebox.showinfo("Data File", "Signature file is successfully added")
                f5.close()
            except:
                messagebox.showerror("ERROR","No signature file selected.")
            
        def open_publickey():
            try:
                global public_f
                file_name2 = filedialog.askopenfilename(initialdir ="Desktop", title = "Open File", filetypes = (("Key File", "*.PEM"),("Text Files", "*.txt") ) ) 
                f2 = open(file_name2, 'rb')
                public_f = f2.read()
                messagebox.showinfo("Public Key", "Public key added successfully!")
                f2.close()
            except:
                messagebox.showerror("ERROR","No public key selected.")

        def verify_select(): #function to verify the data
            verify_key = StringVar()
            if algorithm_2.get()==1:
                try:
                    verify_key = signwithRSA.verify_signature(public_f, data_filev, file_name5)
                    messagebox.showinfo("Complete", "Verification Request Complete. Check the terminal for result.")
                except:
                    messagebox.showerror("ERROR", " Incorrect Syntax, Check the inputs")
            elif algorithm_2.get()==2:
                try:
                    verify_key = signwithDSA.verify_signature(public_f, data_filev, file_name5)
                    messagebox.showinfo("Complete", "Verification Request Complete Check the terminal for result.")
                except:
                    messagebox.showerror("ERROR", " Incorrect Syntax, Check the inputs")
            elif algorithm_2.get()==3:
                try:
                    verify_key = signwithECC.verify_signature(public_f, data_filev, file_name5)
                    messagebox.showinfo("Complete", "Verification Request Complete Check the terminal for result.")
                except:
                    messagebox.showerror("ERROR", " Incorrect Syntax, Check the inputs")
            else:
                messagebox.showerror("ERROR", " Incorrect Parameters. Check the key file or algorithm")

#--------------------------------------MAIN----------------------------

gui = Tk()
gui.title("DSignify") #changing title
gui.geometry("505x500+500+100") #setting size
gui.iconbitmap(os.path.abspath(__file__ + "\..\guiconmain.ico")) #changing icon
gui.resizable(False, False)

notebook = ttk.Notebook(gui)

frame1 = ttk.Frame(notebook)
frame2 = ttk.Frame(notebook)
frame3 = ttk.Frame(notebook)
notebook.add(frame1, text="Generate Keys")
notebook.add(frame2, text="Sign Document")
notebook.add(frame3, text ="Verify Document")
notebook.pack()
#now = datetime.datetime.now()

if __name__ == "__main__":
    Generate(gui)
    Sign(gui)
    Verify(gui)

    messagebox.showinfo("Disclaimer", "This is a prototype to demonstrate key generation, sign and verify documents.\n"
                        "\u00A9 2021, Yaman Shrestha")
    gui.mainloop()
