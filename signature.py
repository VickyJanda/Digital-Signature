import PyPDF2
import cryptography
from pdfrw import PdfReader, PdfWriter 
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
import os

# Function to extract text from a PDF file
def extract_text_from_pdf(pdf_path):
    text = ""
    with open(pdf_path, 'rb') as file:
        reader = PyPDF2.PdfReader(file)
        for page in reader.pages:
            text += page.extract_text()
    return text

def extract_text_from_txt(txt_path):
    try:
        with open(txt_path, "r") as file:
            text = file.read()
    except FileNotFoundError:
        print("File not found.")
    except Exception as e:
        print("An error occurred:", e)
    return text

def extract_signed_text_from_txt(txt_path):
    try:
        with open(txt_path, "r") as file:
            text = file.read()
            signature_start = text.find('\n\n-----BEGIN SIGNATURE-----\n')
            text = text[:signature_start]
    except FileNotFoundError:
        print("File not found.")
    except Exception as e:
        print("An error occurred:", e)
    return text


# Function to extract ciphertext from the PDF metadata
def extract_ciphertext_from_pdf(pdf_path):
    trailer = PdfReader(pdf_path)
    ciphertext_hex = trailer.Info.hash[1:][:-1]
    print("Cipher:",ciphertext_hex)

    try:
        # Ensure the string is in the correct format (e.g., remove any leading or trailing whitespace)
        ciphertext_hex = ciphertext_hex.strip()

        # Convert hexadecimal string back to bytes
        ciphertext = bytes.fromhex(ciphertext_hex)
        return ciphertext
    except ValueError as e:
        print("Error extracting ciphertext:", e)
        print("Signature verification failed!")
        exit (1)
        return None


def extract_public_key_from_pdf(pdf_path):
    try:
        # Read the PDF file and load its metadata
        trailer = PdfReader(pdf_path)
        # Access the custom field containing the public key
        public_key_str = trailer.Info.public_key[1:][:-1]
        #public_key_str = public_key_str.replace('\\n', '\n') 
        print(public_key_str)
        
        # Decode the public key string
        public_key_pem = public_key_str.encode('utf-8')
        
        # Deserialize the public key from PEM format
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

        return public_key
    except Exception as e:
        print("Error extracting public key:", e)
        print("Signature verification failed!")
        exit (1)
        return None


# Generate RSA keys
def key_gen():
    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def str_key(public_key):
    # Serialize the RSA public key to PEM format
    public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Encode the PEM-formatted public key as a string
    public_key_str = public_key_pem.decode('utf-8')
    return public_key_str

def sign(private_key,hash_value):
    # Encrypt the hash value with the public key
    ciphertext = private_key.sign(
    hash_value,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
    )
    return ciphertext

def verify(public_key,ciphertext,hash_value):
    public_key.verify(
        ciphertext,
        hash_value,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
def save_signature_and_key(signature, public_key, txt_path):
    with open(txt_path, 'a') as file:
        file.write('\n\n-----BEGIN SIGNATURE-----\n')
        file.write(signature.hex())
        file.write('\n-----END SIGNATURE-----\n')
        file.write('\n-----BEGIN PUBLIC KEY-----\n')
        file.write(str_key(public_key))
        file.write('\n-----END PUBLIC KEY-----\n')

def extract_signature_and_key(txt_content):
    signature_start = txt_content.find('-----BEGIN SIGNATURE-----')
    signature_end = txt_content.find('-----END SIGNATURE-----')
    public_key_start = txt_content.find('-----BEGIN PUBLIC KEY-----')
    public_key_end = txt_content.find('-----END PUBLIC KEY-----')

    if signature_start != -1 and signature_end != -1 and public_key_start != -1 and public_key_end != -1:
        signature = bytes.fromhex(txt_content[signature_start + len('-----BEGIN SIGNATURE-----'):signature_end].strip())

        # Extract the entire public key substring
        public_key_str = (txt_content[public_key_start + len('-----BEGIN PUBLIC KEY-----'):public_key_end]+'-----END PUBLIC KEY-----').strip()

        print("Public key PEM:\n", public_key_str)  # Debugging print statement

        try:
            public_key = serialization.load_pem_public_key(public_key_str.encode('utf-8'), backend=default_backend())
            return signature, public_key
        except Exception as e:
            print("Error loading public key:", e)
            return None, None
    else:
        print("Signature and/or public key not found in the text file.")  # Debugging print statement
        return None, None


  

#####################________MAIN_FUNCTION_________###################

# Path to the original PDF
pdf_path = 'lorem.pdf'
txt_path = 'lorem.txt'

choice = input("Choose action:\nPress '1' for signing\nPress '2' for verification\n")

if(choice == "1"):
    format = input("Choose file format:\nPress '1' for pdf\nPress '2' for txt\n")
    if(format == "1"):
        print("Generating keys...")
        private_key, public_key=key_gen()
    
        print("Creating hash...")
        # Extract text from the PDF
        pdf_text = extract_text_from_pdf(pdf_path)
        # Hash the text
        hash_value = hashlib.sha256(pdf_text.encode('utf-8')).digest()

        print("Signing PDF...")
        ciphertext = sign(private_key,hash_value)

        # Embed the ciphertext as metadata in the PDF file
        trailer = PdfReader(pdf_path)
        trailer.Info.hash = ciphertext.hex()  # Store the ciphertext as hexadecimal string
        trailer.Info.public_key = str_key(public_key)
        PdfWriter(pdf_path, trailer=trailer).write()
        print("PDF signed successfully!")
    if(format == "2"):
        print("Generating keys...")
        private_key, public_key=key_gen()
    
        print("Creating hash...")
        txt_text = extract_text_from_txt(txt_path)
        
        if txt_text:
            # Hash the text
            hash_value = hashlib.sha256(txt_text.encode('utf-8')).digest()
            print("Signing txt...")
            signature = sign(private_key, hash_value)

            # Save signature and public key
            save_signature_and_key(signature, public_key, txt_path)
            print("Text file signed successfully!")
    
if(choice == "2"):
    format = input("Choose file format:\nPress '1' for pdf\nPress '2' for txt\n")
    if(format == "1"):

        print("Extracting key and hash from pdf...")
        public_key = extract_public_key_from_pdf(pdf_path)
        # Read the PDF file and load its metadata
        ciphertext = extract_ciphertext_from_pdf(pdf_path)
    
        print("Hashing PDF contents...")
        # Extract text from the PDF
        pdf_text = extract_text_from_pdf(pdf_path)
        # Hash the text
        hash_value = hashlib.sha256(pdf_text.encode('utf-8')).digest()
        
        # Decrypt the ciphertext with the private key
        print("Verifying signature...")
        try:
            verify(public_key,ciphertext,hash_value)
            print("Signature verified successfully!")
        except cryptography.exceptions.InvalidSignature:
            print("Signature verification failed!")
    if(format == "2"):
        
        print("Verifying signature...")

        txt_text = extract_text_from_txt(txt_path)
        if txt_text:
            signature, public_key = extract_signature_and_key(txt_text)
            if signature and public_key:
                #Hash the text
                txt_text = extract_signed_text_from_txt(txt_path)
                hash_value = hashlib.sha256(txt_text.encode('utf-8')).digest()
                

                # Verify signature
                try:
                    verify(public_key,signature,hash_value)
                    print("Signature verified successfully!")
                except cryptography.exceptions.InvalidSignature:
                    print("Signature verification failed!")
