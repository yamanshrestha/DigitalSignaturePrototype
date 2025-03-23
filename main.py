import os
import sys
from tkinter import *
from tkinter import ttk, filedialog, messagebox
import tkinter as tk

import key_RSA
import key_DSA
import key_ECC
import key_ElGamal
import signwithRSA
import signwithDSA
import signwithECC

# ------------------- Generate Keys Tab -------------------
class Generate(ttk.Frame):
    def __init__(self, parent, main_app):
        super().__init__(parent)
        self.main_app = main_app
        self.pack(fill=BOTH, expand=True)
        self.create_widgets()
    
    def create_widgets(self):
        # Algorithm selection group
        alg_frame = ttk.LabelFrame(self, text="Choose Algorithm")
        alg_frame.pack(fill=X, padx=10, pady=5)
        ttk.Label(alg_frame, text="Choose the type of key you want to generate").pack(anchor=W, padx=5, pady=2)
        
        # Parameters subframe for bit size and curve
        param_frame = ttk.Frame(alg_frame)
        param_frame.pack(fill=X, padx=5, pady=2)
        self.bits = IntVar(value=1024)
        ttk.Label(param_frame, text="Bit Size:").pack(side=LEFT, padx=5)
        ttk.Entry(param_frame, textvariable=self.bits, width=10).pack(side=LEFT, padx=5)
        self.curve = StringVar(value="secp256r1")
        ttk.Label(param_frame, text="Curve:").pack(side=LEFT, padx=5)
        self.curve_combo = ttk.Combobox(param_frame, textvariable=self.curve, width=15)
        self.curve_combo['values'] = (
            "p256", "NIST P-256", "P-256", "prime256v1", "secp256r1", "nistp256",
            "p384", "NIST P-384", "P-384", "prime384v1", "secp384r1", "nistp384",
            "p521", "NIST P-521", "P-521", "prime521v1", "secp521r1", "nistp521"
        )
        self.curve_combo.current(4)
        self.curve_combo.pack(side=LEFT, padx=5)
        
        # Radiobuttons for algorithm selection
        self.algorithm = IntVar(value=1)
        radio_frame = ttk.Frame(alg_frame)
        radio_frame.pack(fill=X, padx=5, pady=2)
        ttk.Radiobutton(radio_frame, text="RSA", variable=self.algorithm, value=1).pack(side=LEFT, padx=5)
        ttk.Radiobutton(radio_frame, text="DSA", variable=self.algorithm, value=2).pack(side=LEFT, padx=5)
        ttk.Radiobutton(radio_frame, text="ECC", variable=self.algorithm, value=3).pack(side=LEFT, padx=5)
        ttk.Radiobutton(radio_frame, text="ElGamal", variable=self.algorithm, value=4).pack(side=LEFT, padx=5)
        
        # Direction group
        dir_frame = ttk.LabelFrame(self, text="Direction")
        dir_frame.pack(fill=X, padx=10, pady=5)
        # Top row: generate key label and button
        top_dir = ttk.Frame(dir_frame)
        top_dir.pack(fill=X, padx=5, pady=2)
        ttk.Label(top_dir, text="Generate Public/Private Key").pack(side=LEFT, padx=5)
        ttk.Button(top_dir, text="Generate Key", command=self.generate_key).pack(side=RIGHT, padx=5)
        # Bottom row: load key label and buttons
        bottom_dir = ttk.Frame(dir_frame)
        bottom_dir.pack(fill=X, padx=5, pady=2)
        ttk.Label(bottom_dir, text="Load Existing Key").pack(side=LEFT, padx=5)
        ttk.Button(bottom_dir, text="Load Public Key", command=self.load_public_key).pack(side=RIGHT, padx=5)
        ttk.Button(bottom_dir, text="Load Private Key", command=self.load_private_key).pack(side=RIGHT, padx=5)
        
        # Key display group
        key_frame = ttk.LabelFrame(self, text="Key")
        key_frame.pack(fill=BOTH, expand=True, padx=10, pady=5)
        disp_frame = ttk.Frame(key_frame)
        disp_frame.pack(fill=BOTH, expand=True, padx=5, pady=5)
        left_disp = ttk.Frame(disp_frame)
        left_disp.pack(side=LEFT, fill=BOTH, expand=True, padx=5)
        ttk.Label(left_disp, text="Private Key").pack(anchor=W)
        self.private_text = Text(left_disp, width=30, height=10)
        self.private_text.pack(fill=BOTH, expand=True, padx=5, pady=5)
        right_disp = ttk.Frame(disp_frame)
        right_disp.pack(side=LEFT, fill=BOTH, expand=True, padx=5)
        ttk.Label(right_disp, text="Public Key").pack(anchor=W)
        self.public_text = Text(right_disp, width=30, height=10)
        self.public_text.pack(fill=BOTH, expand=True, padx=5, pady=5)

    def save_keypair(self, private_key, public_key, label="RSA"):
        root = tk.Tk()
        root.withdraw()
        filetypes = [
            ("Key File", "*.pem"),
            ("Text File", "*.txt"),
            ("Raw Key File", "*.key")
        ]
        # Ask for private key file path
        private_key_path = filedialog.asksaveasfilename(
            title=f"Save {label} Private Key As",
            defaultextension=".pem",
            filetypes=filetypes,
            initialfile=f"PrivateKey{label}",
            parent=root
        )
        if not private_key_path:
            messagebox.showwarning("Cancelled", f"{label} key generation cancelled. No private key file selected.", parent=root)
            root.destroy()
            return False

        # Ask for public key file path
        public_key_path = filedialog.asksaveasfilename(
            title=f"Save {label} Public Key As",
            defaultextension=".pem",
            filetypes=filetypes,
            initialfile=f"PublicKey{label}",
            parent=root
        )
        if not public_key_path:
            messagebox.showwarning("Cancelled", f"{label} key generation cancelled. No public key file selected.", parent=root)
            root.destroy()
            return False

        try:
            with open(private_key_path, 'wb') as f:
                f.write(private_key)

            with open(public_key_path, 'wb') as f:
                f.write(public_key)

            messagebox.showinfo("Success", f"{label} key pair saved successfully!", parent=root)
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save {label} keys:\n{e}", parent=root)
            return False
        finally:
            root.destroy()


    def generate_key(self):
        try:
            alg = self.algorithm.get()
            # Use different minimum bitsize requirements based on algorithm:
            if alg == 4:
                # For ElGamal, require at least 256 bits
                if self.bits.get() < 256:
                    messagebox.showerror("ERROR", "For ElGamal, the bitsize must be >= 256")
                    return
            else:
                # For RSA, DSA, etc., require at least 1024 bits
                if self.bits.get() < 1024:
                    messagebox.showerror("ERROR", "The bitsize must be >= 512")
                    return
                
            if alg == 1:
                key_pair= key_RSA.generate(self.bits.get())
                private_key, public_key = key_pair
                if self.save_keypair(private_key, public_key, label="RSA"):
                    messagebox.showinfo("Success", "RSA keys are also stored successfylly.")
                else:
                    return
            elif alg == 2:
                key_pair = key_DSA.generate(self.bits.get())
                private_key, public_key = key_pair
                if self.save_keypair(private_key, public_key, label="DSA"):
                    messagebox.showinfo("Success", "DSA keys are also stored successfylly.")
                else:
                    return
            elif alg == 3:
                key_pair = key_ECC.generate(self.curve.get())
                private_key, public_key = key_pair
                if self.save_keypair(private_key, public_key, label="ECC"):
                    messagebox.showinfo("Success", "ECC keys are also stored successfylly.")
                else:
                    return
            elif alg == 4:
                key_pair = key_ElGamal.generate(self.bits.get())
                private_key, public_key = key_pair
                if self.save_keypair(private_key, public_key, label="ElGamel"):
                    messagebox.showinfo("Success", "ElGamel keys are also stored successfylly.")
                else:
                    return
            else:
                messagebox.showerror("ERROR", "No valid algorithm selected.")
                return
            
            self.main_app.current_private_key = key_pair[0]
            self.main_app.current_public_key = key_pair[1]           
            # Display the keys (assuming key_pair is a tuple: (private, public))
            self.private_text.delete("1.0", END)
            self.private_text.insert(END, key_pair[0])
            self.public_text.delete("1.0", END)
            self.public_text.insert(END, key_pair[1])
        except Exception as e:
            messagebox.showerror("ERROR", f"Key generation failed: {e}")
    
    def load_private_key(self):
        try:
            filepath = filedialog.askopenfilename(initialdir="Desktop", title="Open Private Key File",
                                                  filetypes=(("Key File","*.pem"), ("Text Files", "*.txt"), ("All Files", "*.*")))
            if not filepath:
                return
            with open(filepath, 'r') as f:
                key_data = f.read()
            self.main_app.current_private_key = key_data
            self.private_text.delete("1.0", END)
            self.private_text.insert(END, key_data)
            messagebox.showinfo("Private Key", "Private key loaded successfully!")
        except Exception as e:
            messagebox.showerror("ERROR", f"Failed to load private key: {e}")
    
    def load_public_key(self):
        try:
            filepath = filedialog.askopenfilename(initialdir="Desktop", title="Open Public Key File",
                                                  filetypes=(("Key File","*.pem"), ("Text Files", "*.txt"), ("All Files", "*.*")))
            if not filepath:
                return
            with open(filepath, 'r') as f:
                key_data = f.read()
            self.main_app.current_public_key = key_data
            self.public_text.delete("1.0", END)
            self.public_text.insert(END, key_data)
            messagebox.showinfo("Public Key", "Public key loaded successfully!")
        except Exception as e:
            messagebox.showerror("ERROR", f"Failed to load public key: {e}")

# ------------------- Sign Document Tab -------------------
class Sign(ttk.Frame):
    def __init__(self, parent, main_app):
        super().__init__(parent)
        self.main_app = main_app
        self.pack(fill=BOTH, expand=True)
        self.create_widgets()
        self.private_key= None
    
    def create_widgets(self):
        # Info area at the top
        info_frame = ttk.Frame(self)
        info_frame.pack(fill=X, padx=10, pady=5)
        
        # Algorithm selection
        alg_frame = ttk.LabelFrame(self, text="Choose Algorithm")
        alg_frame.pack(fill=X, padx=10, pady=5)
        ttk.Label(alg_frame, text="Choose the type of key to sign Document.").pack(anchor=W, padx=5, pady=2)
        self.algorithm_1 = IntVar(value=1)
        radio_frame = ttk.Frame(alg_frame)
        radio_frame.pack(fill=X, padx=5, pady=2)
        ttk.Radiobutton(radio_frame, text="RSA", variable=self.algorithm_1, value=1).pack(side=LEFT, padx=5)
        ttk.Radiobutton(radio_frame, text="DSA", variable=self.algorithm_1, value=2).pack(side=LEFT, padx=5)
        ttk.Radiobutton(radio_frame, text="ECC", variable=self.algorithm_1, value=3).pack(side=LEFT, padx=5)
        ttk.Button(alg_frame, text="View Info", command=self.show_info).pack(side=RIGHT, padx=5)
        
        # Direction for signing (file selection and signature filename)
        dir_frame = ttk.LabelFrame(self, text="Direction")
        dir_frame.pack(fill=X, padx=10, pady=5)
        file_frame = ttk.Frame(dir_frame)
        file_frame.pack(fill=X, padx=5, pady=2)
        ttk.Label(file_frame, text="Choose the file you wish to sign:").pack(side=LEFT, padx=5)
        self.file_path = StringVar()
        ttk.Entry(file_frame, textvariable=self.file_path, width=40).pack(side=LEFT, padx=5)
        ttk.Button(file_frame, text="...", command=self.select_data_file).pack(side=LEFT, padx=5)
        
        sig_frame = ttk.Frame(dir_frame)
        sig_frame.pack(fill=X, padx=5, pady=2)
        ttk.Label(sig_frame, text="Enter signature file name:").pack(side=LEFT, padx=5)
        self.sig_filename = StringVar()
        ttk.Entry(sig_frame, textvariable=self.sig_filename, width=40).pack(side=LEFT, padx=5)
        
        # Key group for signing
        key_frame = ttk.LabelFrame(self, text="Key")
        key_frame.pack(fill=X, padx=10, pady=5)
        btn_frame = ttk.Frame(key_frame)
        btn_frame.pack(fill=X, padx=5, pady=5)
        ttk.Button(btn_frame, text="Load Private Key", command=self.load_private_key).pack(side=LEFT, padx=5)
        ttk.Button(btn_frame, text="Sign", command=self.sign_document).pack(side=LEFT, padx=5)
    
    def show_info(self):
        info = (
            "The following syntax is followed to sign and verify:\n"
            "<signing_algorithm> -s <private_key> <data to be signed> <signature-file>\n"
            "<same_algorithm> -v <PUB-key> <data to be verified> <signature-file>"
        )
        messagebox.showinfo("DISCLAIMER", info)
    
    def select_data_file(self):
        try:
            filepath = filedialog.askopenfilename(initialdir="Desktop", title="Select File to Sign",
                                                  filetypes=(("File","*"), ("Text Files", "*.txt"), ("All Files", "*.*")))
            if filepath:
                self.file_path.set(filepath)
        except Exception as e:
            messagebox.showerror("ERROR", f"Error selecting file: {e}")
    
    def load_private_key(self):
        self.private_key = f.read()
        try:
            filepath = filedialog.askopenfilename(initialdir="Desktop", title="Select Private Key",
                                                  filetypes=(("Key File","*.pem"), ("Text Files", "*.txt"), ("All Files", "*.*")))
            if not filepath:
                return
            with open(filepath, 'rb') as f:
                self.private_key = f.read()
            messagebox.showinfo("Private Key", "Private key loaded successfully!")
        except Exception as e:
            messagebox.showerror("ERROR", f"Error loading private key: {e}")
    
    def sign_document(self):
        try:
            # 1) Determine which private key to use
            if not hasattr(self, 'private_key') or self.private_key is None:
                # Fallback to the main app's current_private_key
                if not hasattr(self.main_app, 'current_private_key') or not self.main_app.current_private_key:
                    messagebox.showerror("ERROR", "No private key loaded in this tab or globally!")
                    return
                else:
                    private_key = self.main_app.current_private_key
            else:
                private_key = self.private_key
                
            if not self.file_path.get():
                messagebox.showerror("ERROR", "No file selected to sign")
                return
            if not self.sig_filename.get():
                messagebox.showerror("ERROR", "No signature filename provided")
                return
            alg = self.algorithm_1.get()
            with open(self.file_path.get(), 'rb') as f:
                data = f.read()
            if alg == 1:
                signwithRSA.generate_signature(private_key, data,self.file_path.get(), self.sig_filename.get())
                messagebox.showinfo("Complete", "RSA Signature successfully created!")
            elif alg == 2:
                signwithDSA.generate_signature(private_key, data,self.file_path.get(), self.sig_filename.get())
                messagebox.showinfo("Complete", "DSA Signature successfully created!")
            elif alg == 3:
                signwithECC.generate_signature(private_key, data, self.file_path.get(), self.sig_filename.get())
                messagebox.showinfo("Complete", "ECC Signature successfully created!")
            else:
                messagebox.showerror("ERROR", "Invalid algorithm selected")
        except Exception as e:
            messagebox.showerror("ERROR", f"Signing failed: {e}")

# ------------------- Verify Document Tab -------------------
class Verify(ttk.Frame):
    def __init__(self, parent, main_app):
        super().__init__(parent)
        self.main_app = main_app
        self.pack(fill=BOTH, expand=True)
        self.create_widgets()
        self.public_key = None
    
    def create_widgets(self):
        # Algorithm selection group
        alg_frame = ttk.LabelFrame(self, text="Choose Algorithm")
        alg_frame.pack(fill=X, padx=10, pady=5)
        ttk.Label(alg_frame, text="Choose the type of key to verify Document.").pack(anchor=W, padx=5, pady=2)
        self.algorithm_2 = IntVar(value=1)
        radio_frame = ttk.Frame(alg_frame)
        radio_frame.pack(fill=X, padx=5, pady=2)
        ttk.Radiobutton(radio_frame, text="RSA", variable=self.algorithm_2, value=1).pack(side=LEFT, padx=5)
        ttk.Radiobutton(radio_frame, text="DSA", variable=self.algorithm_2, value=2).pack(side=LEFT, padx=5)
        ttk.Radiobutton(radio_frame, text="ECC", variable=self.algorithm_2, value=3).pack(side=LEFT, padx=5)
        ttk.Button(alg_frame, text="View Info", command=self.show_info).pack(side=RIGHT, padx=5)
        
        # File selection for verification
        dir_frame = ttk.LabelFrame(self, text="Direction")
        dir_frame.pack(fill=X, padx=10, pady=5)
        file_frame = ttk.Frame(dir_frame)
        file_frame.pack(fill=X, padx=5, pady=2)
        ttk.Label(file_frame, text="Choose the file to verify:").pack(side=LEFT, padx=5)
        self.verify_file_path = StringVar()
        ttk.Entry(file_frame, textvariable=self.verify_file_path, width=40).pack(side=LEFT, padx=5)
        ttk.Button(file_frame, text="...", command=self.select_verify_file).pack(side=LEFT, padx=5)
        
        sig_frame = ttk.Frame(dir_frame)
        sig_frame.pack(fill=X, padx=5, pady=2)
        ttk.Label(sig_frame, text="Choose the signature file:").pack(side=LEFT, padx=5)
        self.sig_verify_path = StringVar()
        ttk.Entry(sig_frame, textvariable=self.sig_verify_path, width=40).pack(side=LEFT, padx=5)
        ttk.Button(sig_frame, text="...", command=self.select_signature_file).pack(side=LEFT, padx=5)
        
        # Key group for verification
        key_frame = ttk.LabelFrame(self, text="Key")
        key_frame.pack(fill=X, padx=10, pady=5)
        btn_frame = ttk.Frame(key_frame)
        btn_frame.pack(fill=X, padx=5, pady=5)
        ttk.Button(btn_frame, text="Load Public Key", command=self.load_public_key).pack(side=LEFT, padx=5)
        ttk.Button(btn_frame, text="Verify", command=self.verify_document).pack(side=LEFT, padx=5)
    
    def show_info(self):
        info = (
            "The following syntax is followed to sign and verify:\n"
            "<signing_algorithm> -s <private_key> <data to be signed> <signature-file>\n"
            "<same_algorithm> -v <PUB-key> <data to be verified> <signature-file>"
        )
        messagebox.showinfo("DISCLAIMER", info)
    
    def select_verify_file(self):
        try:
            filepath = filedialog.askopenfilename(initialdir="Desktop", title="Select File to Verify",
                                                  filetypes=(("Text Files", "*.txt"), ("All Files", "*.*")))
            if filepath:
                self.verify_file_path.set(filepath)
        except Exception as e:
            messagebox.showerror("ERROR", f"Error selecting file: {e}")
    
    def select_signature_file(self):
        try:
            filepath = filedialog.askopenfilename(initialdir="Desktop", title="Select Signature File",
                                                  filetypes=(("Signature File","*"), ("Text Files", "*.txt"), ("All Files", "*.*")))
            if filepath:
                self.sig_verify_path.set(filepath)
        except Exception as e:
            messagebox.showerror("ERROR", f"Error selecting signature file: {e}")
    
    def load_public_key(self):
        self.public_key = f.read()
        try:
            filepath = filedialog.askopenfilename(initialdir="Desktop", title="Select Public Key",
                                                  filetypes=(("Key File","*.pem"), ("Text Files", "*.txt"), ("All Files", "*.*")))
            if not filepath:
                return
            with open(filepath, 'rb') as f:
                self.public_key = f.read()
            messagebox.showinfo("Public Key", "Public key loaded successfully!")
        except Exception as e:
            messagebox.showerror("ERROR", f"Error loading public key: {e}")
    
    def verify_document(self):
        try:
            # 1) Determine which private key to use
            if not hasattr(self, 'public_key') or self.public_key is None:
                # Fallback to the main app's current_public_key
                if not hasattr(self.main_app, 'current_public_key') or not self.main_app.current_public_key:
                    messagebox.showerror("ERROR", "No public key loaded in this tab or globally!")
                    return
                else:
                    public_key = self.main_app.current_public_key
            else:
                public_key = self.public_key
            if not self.verify_file_path.get():
                messagebox.showerror("ERROR", "No file selected for verification")
                return
            if not self.sig_verify_path.get():
                messagebox.showerror("ERROR", "No signature file selected")
                return
            alg = self.algorithm_2.get()
            with open(self.verify_file_path.get(), 'rb') as f:
                data = f.read()
            if alg == 1:
                result = signwithRSA.verify_signature(public_key, data, self.sig_verify_path.get())
                #messagebox.showinfo("Verification result", result)
            elif alg == 2:
                result = signwithDSA.verify_signature(public_key, data, self.sig_verify_path.get())
                messagebox.showinfo("Verification result", result)
            elif alg == 3:
                result = signwithECC.verify_signature(public_key, data, self.sig_verify_path.get())
                #messagebox.showinfo("Verification result", result)
            else:
                messagebox.showerror("ERROR", "Invalid algorithm selected")

            if result == "Verification Failure":
                messagebox.showerror("Failed", result)
            else:
                messagebox.showinfo("Verification Result", result)
        except Exception as e:
            messagebox.showerror("ERROR", f"Verification failed: {e}")

# ------------------- Main Application -------------------
def main():
    gui = Tk()

    gui.current_private_key = None
    gui.current_public_key = None
    style = ttk.Style(gui)
    style.theme_use("clam")
    gui.title("Digital Signature")
    base_dir = os.path.dirname(os.path.abspath(__file__))

    # Cross-platform icon handling
    if sys.platform.startswith('win'):
        icon_path = os.path.join(base_dir, "guiconmain.ico")
        if os.path.exists(icon_path):
            gui.iconbitmap(icon_path)
        else:
            print("Icon file not found:", icon_path)
    else:
        icon_path = os.path.join(base_dir, "guiconmain.png")
        if os.path.exists(icon_path):
            icon = PhotoImage(file=icon_path)
            gui.iconphoto(False, icon)
        else:
            print("Icon file not found:", icon_path)

    gui.geometry("700x600+500+200")  # initial size and position
    gui.minsize(700,600)           # minimum size
    gui.resizable(True, True)       # allow resizing

    notebook = ttk.Notebook(gui)
    notebook.pack(fill=BOTH, expand=True)
    
    frame1 = ttk.Frame(notebook)
    frame2 = ttk.Frame(notebook)
    frame3 = ttk.Frame(notebook)
    notebook.add(frame1, text="Generate Keys")
    notebook.add(frame2, text="Sign Document")
    notebook.add(frame3, text="Verify Document")

    Generate(frame1, gui)
    Sign(frame2, gui)
    Verify(frame3, gui)

    gui.mainloop()

if __name__ == "__main__":
    main()
