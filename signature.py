import PyPDF2
import cryptography
from pdfrw import PdfReader, PdfWriter 
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
import base64

# Function to extract text from a PDF file
def extract_text_from_pdf(pdf_path):
    text = ""
    with open(pdf_path, 'rb') as file:
        reader = PyPDF2.PdfReader(file)
        for page in reader.pages:
            text += page.extract_text()
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
        return None


def extract_public_key_from_pdf(pdf_path):
    try:
        # Read the PDF file and load its metadata
        trailer = PdfReader(pdf_path)
        # Access the custom field containing the public key
        public_key_str = trailer.Info.public_key[1:][:-1]
        print(public_key_str)
        
        # Decode the public key string
        public_key_pem = public_key_str.encode('utf-8')
        
        # Deserialize the public key from PEM format
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
        
        return public_key
    except Exception as e:
        print("Error extracting public key:", e)
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

def sign_pdf(private_key,hash_value):
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

def verify_pdf(public_key,ciphertext,hash_value):
    public_key.verify(
        ciphertext,
        hash_value,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

#####################________MAIN_FUNCTION_________###################

# Path to the original PDF
pdf_path = 'lorem3.pdf'

choice = input("Choose action:\nPress '1' for signing\nPress '2' for verification\n")

if(choice == "1"):
    print("Generating keys...")
    private_key, public_key=key_gen()
    
    print("Creating hash...")
    # Extract text from the PDF
    pdf_text = extract_text_from_pdf(pdf_path)
    # Hash the text
    hash_value = hashlib.sha256(pdf_text.encode('utf-8')).digest()

    print("Signing PDF...")
    ciphertext = sign_pdf(private_key,hash_value)

    # Embed the ciphertext as metadata in the PDF file
    trailer = PdfReader(pdf_path)
    trailer.Info.hash = ciphertext.hex()  # Store the ciphertext as hexadecimal string
    trailer.Info.public_key = str_key(public_key)
    PdfWriter(pdf_path, trailer=trailer).write()
    print("PDF signed successfully!")
    
if(choice == "2"):

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
        verify_pdf(public_key,ciphertext,hash_value)
        print("Signature verified successfully!")
    except cryptography.exceptions.InvalidSignature:
        print("Signature verification failed!")
    