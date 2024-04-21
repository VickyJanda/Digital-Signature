from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
import os
import re


#Returns numbers n and d from a private key
def extract_rsa_private(key):
    n = key.private_numbers().p * key.private_numbers().q
    d = key.private_numbers().d
    return n, d

#Returns numbers n and e from a public key
def extract_rsa_public(key):
    n = key.public_numbers().n
    e = key.public_numbers().e
    return n, e

#Generates private and public keys
def key_gen():
    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

#Returns public key as string instead of RSA object
def str_key(public_key):
    # Serialize the RSA public key to PEM format
    public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Encode the PEM-formatted public key as a string
    public_key_str = public_key_pem.decode('utf-8')
    return public_key_str

#Returns private key as string instead of RSA object
def str_keys(private_key):
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_str = private_key_pem.decode('utf-8')
    return private_key_str
    
#Custom function for RSA signature
def my_sign(private_key,hash_value):
    n_private, d = extract_rsa_private(private_key)
    ciphertext = pow(int.from_bytes(hash_value,'big'),d,n_private)
    return hex(ciphertext)[2:]

#Custom function for RSA verification
def my_verify(public_key,signature,hash_value):
    n_public, e = extract_rsa_public(public_key)
    new_hash = pow(int(signature,16),e,n_public)
    
    if(int.from_bytes(hash_value,'big') == new_hash):
        print("Signature verified successfully!\n")
    else:
        print("Signature verification FAILED!\n")

#Custom hashing function
def my_hash(content):
    hash_algorithm = hashes.SHA256()
    hasher = hashes.Hash(hash_algorithm,default_backend())
    hasher.update(content.encode('utf-8'))
    hash_value = hasher.finalize()
    return hash_value

#Generates a certificate and a key, saves them in a file.pem and file_privat_key.pem
def generate_certificate():
    private_key, public_key = key_gen()
    country = input("Enter the country name(2 character code): ")
    state = input("Enter the state or province name: ")
    locality = input("Enter the locality name: ")
    organization = input("Enter the organization name: ")
    common_name = input("Enter the common name: ")
    try:
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
    except Exception as e:
        print("Error:", e)
        exit(-1)
        
    # Set the expiration date for the certificate
    current_date = datetime.now()
    expiration_date = current_date + timedelta(days=365)


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


#Reads the data from a signed certificate, returning public key
def extract_certificate(crt_name):
    with open(crt_name, "rb") as cert_file:
        cert_data = cert_file.read()

    # Parse the certificate
    certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

    return certificate.public_key()

#Reads the data from a signed certificate, checking it's validity
def verify_certificate(cert_path):
    # Load the certificate
    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()
        
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())

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

    return True
    
#Saves digital signature in a file
def save_signature(signature, file):  
        file.write('-----BEGIN SIGNATURE-----\n')
        file.write(re.sub("(.{64})", "\\1\n", str(signature), 0, re.DOTALL))
        file.write('-----END SIGNATURE-----\n')

#Exctracts digital signature from a file
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
        print("Signature and/or public key not found in the text file.")
        return None

#####################________MAIN_FUNCTION_________###################

exit_program = False
while(not exit_program):
    choice = input("Choose action:\nPress '1' for creating a certificate\nPress '2' for signing\nPress '3' for verification\nPress '4' to exit\n")
    
    #Menu choice to create a certificate
    if(choice == "1"):
        CA_private_key, certificate,crt_name = generate_certificate()

    #Menu choice to sign a file
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
        with open(txt_key,'w') as signature_file:
            signature_file.truncate(0)
            hash_value = my_hash(file_content)
            
            print("Signing txt...")
            signature = my_sign(private_key, hash_value)
            
            save_signature(signature, signature_file)
            print("Text file signed successfully!\n")
    
    #Menu choice to verify a file's signature    
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
            print("Certificate file doesnt exist, create a certificate first.")
            exit()
        
        if(os.path.isfile(txt_key)):
            with open(txt_key,'r+') as data_pem:
                file_content = data_pem.read()
        else:
            print("Signature file doesnt exist, create a signature first.")
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

        # Verify signature
        print("Verifying signature...")
        if(verify_certificate(crt_path)):
            my_verify(public_key,signature,hash_value)
        else:
            print("Signature verification FAILED!\n")
        
    

    if(choice == "4"):
        exit_program = True

    
                
                
             