from datetime import datetime
import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
import os
import re

# Generate RSA keys

def extract_rsa_private(key):
    n = key.private_numbers().p * key.private_numbers().q
    d = key.private_numbers().d
    return n, d

def extract_rsa_public(key):
    n = key.public_numbers().n
    e = key.public_numbers().e
    return n, e

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

def str_keys(private_key):
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_str = private_key_pem.decode('utf-8')
    return private_key_str
    

def my_sign(private_key,hash_value):
    # Encrypt the hash value with the public key
    n_private, d = extract_rsa_private(private_key)
    ciphertext = pow(int.from_bytes(hash_value,'big'),d,n_private)
    return hex(ciphertext)[2:]

def my_verify(public_key,signature,hash_value):
    n_public, e = extract_rsa_public(public_key)
    new_hash = pow(int(signature,16),e,n_public)
    
    if(int.from_bytes(hash_value,'big') == new_hash):
        print("Signature verified successfully!\n")
    else:
        print("Signature verification FAILED!\n")

def my_hash(content):
    hash_algorithm = hashes.SHA256()
    hasher = hashes.Hash(hash_algorithm,default_backend())
    hasher.update(content.encode('utf-8'))
    hash_value = hasher.finalize()
    return hash_value

def generate_certificate():
    private_key, public_key = key_gen()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"example.com"),
    ])

        # Set the expiration date for the certificate
    expiration_date = datetime(2025, 12, 31)  # Set expiration to December 31, 2025

    # Create a self-signed certificate
    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        subject
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        expiration_date
    ).sign(
        private_key, hashes.SHA256(), default_backend()
    )

    # Export the private key and certificate to files
    crt_input = input("Enter certificate filename:\n").split('.')
    crt_file= crt_input[0]
    
    with open(crt_file +"_private_key.pem", "w") as private_key_file:
       
        private_key_file.write(str_keys(private_key))
       
    print("Private key saved as:"+crt_file +"_private_key.pem")
    
    with open(crt_file +".pem", "wb") as certificate_file:
        certificate_file.write(certificate.public_bytes(serialization.Encoding.PEM))
        
    print("Certificate saved as:"+crt_file +".pem\n")


    return private_key, certificate, crt_file+'.pem'

def extract_certificate(crt_name):
    with open(crt_name, "rb") as cert_file:
        cert_data = cert_file.read()

    # Parse the certificate
    certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

    # Extract information from the certificate
    # print("Subject:")
    # print(certificate.subject)

    # print("\nIssuer:")
    # print(certificate.issuer)

    # print("\nSerial Number:")
    # print(certificate.serial_number)

    # print("\nNot Valid Before:")
    # print(certificate.not_valid_before)

    # print("\nNot Valid After:")
    # print(certificate.not_valid_after)

    # print("\nPublic Key:")
    # print(str_key(certificate.public_key()))

    return certificate.public_key()

def verify_certificate(cert_path):
    # Load the certificate
    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()
        
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    # Verify the certificate signature using trusted certificates
    try:
        cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        print("Certificate signature verified successfully!")
    except Exception as e:
        print("Certificate signature verification failed!", e)
        return False

    # Additional verification checks can be added here (e.g., expiry, revocation, chain validation)

    return True
    
def save_signature(signature, file):  
        file.write('-----BEGIN SIGNATURE-----\n')
        file.write(re.sub("(.{64})", "\\1\n", str(signature), 0, re.DOTALL))
        file.write('-----END SIGNATURE-----\n')

def extract_signature(txt_content):
    signature_start = txt_content.find('-----BEGIN SIGNATURE-----')
    signature_end = txt_content.find('-----END SIGNATURE-----')

    if signature_start != -1 and signature_end != -1:
        try:
            signature = hex(int(txt_content[signature_start + len('-----BEGIN SIGNATURE-----'):signature_end].replace('\n',""),16))
        except Exception as e:
            print("Error loading signature:", e)
            print("Signature verification failed!")
            exit(1)
        try:
            return signature[2:]
        except Exception as e:
            print("Error loading signature:", e)
            print("Signature verification failed!")
            exit(1)

    else:
        print("Signature and/or public key not found in the text file.")  # Debugging print statement
        return None

#####################________MAIN_FUNCTION_________###################

exit_program = False
while(not exit_program):
    choice = input("Choose action:\nPress '1' for creating a certificate\nPress '2' for signing\nPress '3' for verification\nPress '4' to exit\n")
    
    if(choice == "1"):
        CA_private_key, certificate,crt_name = generate_certificate()

    if(choice == "2"):
        crt_name = input("Enter certificate name:\n").split('.')
        crt_path = crt_name[0] + '.pem'
        private_path = crt_name[0] + '_private_key.pem'
        file_path = input("Enter filename to sign:\n")
        file_path_split= file_path.split('.')
        txt_key = file_path_split[0] + '.pem' 
        
        if(os.path.isfile(crt_path)):
            with open(crt_path,'r+') as data_crt:
                crt_content = data_crt.read()
        else:
            print("Certificate file doesnt exist.")
            exit()
            
        if(os.path.isfile(private_path)):
            with open(private_path,'r+') as data_private:
                private_content = data_private.read()
                
            try:
                private_key = serialization.load_pem_private_key(private_content.encode('utf-8'),password = None, backend=default_backend())
            
            except Exception as e:
                print("Error loading private key:", e)
                print("Signature verification failed!")
                exit(1)
        else:
            print("Private key file doesnt exist.")
            exit()
        
        if(os.path.isfile(file_path)):
            with open(file_path,'r+') as data_txt:
                file_content = data_txt.read()
        else:
            print("Data file doesnt exist.")
            exit()    
        
        print("Creating hash...")    
        with open("data.pem",'w') as signature_file:
            signature_file.truncate(0)
            hash_value = my_hash(file_content)
            
            print("Signing txt...")
            signature = my_sign(private_key, hash_value)
            
            save_signature(signature, signature_file)
            print("Text file signed successfully!\n")
        
    if(choice == "3"):
        crt_name = input("Enter certificate name:\n").split('.')
        crt_path = crt_name[0] + '.pem'
        file_path = input("Choose file:\n")
        file_path_split= file_path.split('.')
        txt_key= file_path_split[0] + '.pem'   
        
        if(os.path.isfile(crt_path)):
            with open(crt_path,'r+') as data_crt:
                crt_content = data_crt.read()
        else:
            print("Certificate file doesnt exist.")
            exit()
        
        if(os.path.isfile(txt_key)):
            with open(txt_key,'r+') as data_pem:
                file_content = data_pem.read()
        else:
            print("Data file doesnt exist.")
            exit() 
            
        if(os.path.isfile(file_path)):
            with open(file_path,'r+') as file_orig:
                orig_content = file_orig.read()
        else:
            print("Data file doesnt exist.")
            exit()   
            
        public_key = extract_certificate(crt_path)
        signature = extract_signature(file_content)

        #Hash the text
        print("Creating hash...")            
                
        hash_value = my_hash(orig_content)
        #signature2 = sign(private_key, hash_value)
        # Verify signature
        print("Verifying signature...")
        if(verify_certificate(crt_path)):
            my_verify(public_key,signature,hash_value)
        else:
            print("Signature verification FAILED!\n")
        
    

    if(choice == "4"):
        exit_program = True

    
                
                
             