<<<<<<< HEAD
# DigitalSignaturePrototype

If any error, please move .exe file into desktop
=======
Digital Signature

This project is a Python-based digital signature application that allows users to generate cryptographic key pairs, sign documents, and verify signatures using various algorithms including RSA, DSA, ECC, and ElGamal.

Features
Generate Keys:

Supports RSA, DSA, ECC, and ElGamal key pair generation.

Customizable key parameters (bit size, curve selection for ECC and ElGamal).

Keys are displayed in the GUI and saved in a designated folder.

Sign Document:

Load a private key or use a globally loaded key.

Select a document to sign.

Generate a signature and automatically store the signature and a copy of the original file in a subfolder.

Verify Document:

Load a public key or use a globally loaded key.

Select the document and its corresponding signature file.

Verify the signature and display the result in a dialog box.

User Interface:

Built using Tkinter with a modern TTK theme.

Organized into a Notebook with three tabs: Generate Keys, Sign Document, and Verify Document.

Flexible window sizing with minimum dimensions.

Requirements
Python 3.10+

PyCryptodome: Cryptographic library for RSA, DSA, ECC, and ElGamal key operations.

Install via pip:

```
pip install pycryptodome
```
Tkinter: Comes bundled with Python on Windows; for Linux, install via your package manager (e.g., sudo apt install python3-tk).


**How to Run**
Activate your virtual environment (if you have one):

On Windows:

```
venv\Scripts\activate

```
**Run the application:**
```
python main.py
```

The application window will open with tabs for generating keys, signing documents, and verifying signatures.


**Using the Application**

Generate Keys Tab:

- Choose an algorithm and set the bit size or select a curve (for ECC/ElGamal).

- Click "Generate Key" to generate a key pair.

- The keys will be displayed and stored in a key folder within your project directory.

- You can also load an existing key using the "Load Private Key" or "Load Public Key" buttons.

Sign Document Tab:

- Select the file you wish to sign.

- Enter a signature file name.

- Load the private key if not already loaded (or use the one loaded in the Generate tab).

- Click "Sign" to generate the signature.

- The signature and a copy of the signed file will be stored in a subfolder under the signature folder.

**Verify Document Tab:**

- Select the file and its corresponding signature file.

- Load the public key if not already loaded (or use the one loaded in the Generate tab).

- Click "Verify" to check the signature. The result will be displayed in a dialog box.


**Troubleshooting**
```ModuleNotFoundError:
If you encounter errors related to missing modules (e.g., Crypto), ensure that PyCryptodome is installed in your environment.
```

**Key Loading/Generation Errors:**
Make sure you provide correct file paths when loading keys. The application stores keys in the key folder, so check that folder for the output files.
>>>>>>> source-code
