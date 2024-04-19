import PyPDF2
import cryptography
from pdfrw import PdfReader, PdfWriter 
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
import os

# Generate RSA keys

def extract_rsa_private(key):
    n = key.private_numbers().p * key.private_numbers().q
    d = key.private_numbers().d
    return n, d

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

def str_keys(private_key_pem):
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

        # Print the private key
    print("private:",private_key_pem.decode())
    

def my_sign(private_key,hash_value):
    # Encrypt the hash value with the public key
    n_private, d = extract_rsa_private(private_key)
    ciphertext = pow(int.from_bytes(hash_value,'big'),d,n_private)
    return ciphertext

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
    
def save_signature_and_key(signature, public_key, file):  
        file.write('-----BEGIN SIGNATURE-----\n')
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
        try:
            signature = bytes.fromhex(txt_content[signature_start + len('-----BEGIN SIGNATURE-----'):signature_end].strip())
        except Exception as e:
            print("Error loading signature:", e)
            print("1Signature verification failed!")
            exit(1)
        # Extract the entire public key substring
        public_key_str = (txt_content[public_key_start + len('-----BEGIN PUBLIC KEY-----'):public_key_end]+'-----END PUBLIC KEY-----').strip()

        try:
            public_key = serialization.load_pem_public_key(public_key_str.encode('utf-8'), backend=default_backend())
            return signature, public_key
        except Exception as e:
            print("Error loading public key:", e)
            print("2Signature verification failed!")
            exit(1)
    else:
        print("Signature and/or public key not found in the text file.")  # Debugging print statement
        return None, None


  

#####################________MAIN_FUNCTION_________###################

choice = input("Choose action:\nPress '1' for signing\nPress '2' for verification\n")

if(choice == "1"):
    
    file_path = input("Choose file:\n")
    file_path_split= file_path.split('.')
    txt_key= file_path_split[0] + '.pem' 
    
    if(os.path.isfile(txt_key)):
        data_file = open(file_path,'r+')
        file_content = data_file.read()
    else:
        print("File doesnt exist.")
        exit()    

    print("Generating keys...")
    private_key, public_key=key_gen()
    
    print("Creating hash...")    
    signature_file = open(txt_key,'w')
    hash_value = hashlib.sha256(file_content.encode('utf-8')).digest()
    
    print("Signing txt...")
    signature = sign(private_key, hash_value)

    save_signature_and_key(signature, public_key,  signature_file)
    print("Text file signed successfully!")
    
    
if(choice == "2"):
    file_path = input("Choose file:\n")
    file_path_split= file_path.split('.')
    txt_key= file_path_split[0] + '.pem' 
    print("path:",txt_key)   
    
    if(os.path.isfile(txt_key)):
        signature_file = open(txt_key,'r+')
        txt_text= signature_file.read()
        data_file = open(file_path,'r+')
        file_content = data_file.read()
    else:
        print("file doesnt exist.")
        exit()
          
    if txt_text:
        signature, public_key = extract_signature_and_key(txt_text)
        if signature and public_key:
            #Hash the text
            print("Creating hash...")            
            
            hash_value = hashlib.sha256(file_content.encode('utf-8')).digest()
            #signature2 = sign(private_key, hash_value)
            # Verify signature
            print("Verifying signature...")
            try:
                verify(public_key,signature,hash_value)
                print("Signature verified successfully!")
            except cryptography.exceptions.InvalidSignature:
                print("Signature verification failed!")
                
             