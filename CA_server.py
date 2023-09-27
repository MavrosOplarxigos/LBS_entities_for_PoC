# This file is intended for:
# - The CA server implementation
# - Implementation of all the functions necessary to deal with the related crypto in the scheme

from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
import traceback
import os
from debug_colors import *

PATH_TO_CREDS="../rsa_creds/"
PATH_TO_CA_CERT="../rsa_creds/rsa_CA_certificate.crt"
PATH_TO_CA_PRIVATE="../rsa_creds/rsa_CA_private.key"
CA_CERTIFICATE = None
CA_PRIVATE = None

def path_to_node_cert_by_name(name):
    return PATH_TO_CREDS + "rsa_" + name + "_certificate.crt"

def path_to_node_private_by_name(name):
    return PATH_TO_CREDS + "rsa_" + name + "_private.key"

def path_to_node_Pcert_by_name(name,index):
    return PATH_TO_CREDS + "rsa_" + name + f"_Pcert{index}.crt"

def path_to_node_Pprivate_by_name(name,index):
    return PATH_TO_CREDS + "rsa_" + name + f"_Pprivate{index}.key"

def file_as_byte_array(path):
    with open(path,"rb") as f:
        return f.read()

def exists_name(name):
    # we want to check if the name the user requested is registered or not
    certificate_path = path_to_node_cert_by_name(name)
    try:
        with open(certificate_path,"rb") as cert_file:
            return True
    except FileNotFoundError:
        return False
    except Exception as e:
        print("Error:",e)
        return False

def retrieve_CA_certificate():
    read_CA_certificate_from_file()
    return CA_CERTIFICATE

def retrieved_CA_private():
    read_CA_private_from_file()
    return CA_PRIVATE

def read_CA_private_from_file():
    global CA_PRIVATE
    with open(PATH_TO_CA_PRIVATE,"rb") as private_key_file:
        private_key_bytes = private_key_file.read()
        CA_PRIVATE = load_pem_private_key(private_key_bytes, password=None, backend=default_backend())

def read_private_from_file_as_byte_array(name):
    path = path_to_node_private_by_name(name)
    try:
        with open(path,"rb") as private_file:
            return private_file.read()
    except FileNotFoundError:
        print(f"{RED}Private key file for {name} was not found!{RESET}")
        return None
    except Exception as e:
        print("Error:",e)
        return None

def read_certificate_from_file_as_byte_array(name):
    path = path_to_node_cert_by_name(name)
    try:
        with open(path,"rb") as cert_file:
            return cert_file.read()
    except FileNotFoundError:
        print(f"{RED}Certificate file for {name} was not found!{RESET}")
        return None
    except Exception as e:
        print("Error:",e)
        return None

def read_certificate_from_file(path):
    with open(path,"rb") as cert_file:
        certificate_bytes = cert_file.read()
        return x509.load_pem_x509_certificate(certificate_bytes, default_backend())

def read_CA_certificate_from_file_as_byte_array():
    try:
        with open(PATH_TO_CA_CERT,"rb") as cert_file:
            return cert_file.read()
    except FileNotFoundError:
        print(f"{RED}CA certificate file not found in {PATH_TO_CA_CERT}{RESET}")
        return None
    except Exception as e:
        print("Error:",e)
        return None

def read_CA_certificate_from_file():
    global CA_CERTIFICATE
    with open(PATH_TO_CA_CERT,"rb") as cert_file:
        certificate_bytes = cert_file.read()
        CA_CERTIFICATE = x509.load_pem_x509_certificate(certificate_bytes, default_backend())

def print_cert_details(certificate):
    print("Version:", certificate.version)
    print("Subject:", certificate.subject.rfc4514_string())
    print("Issuer:", certificate.issuer.rfc4514_string())
    print("Valid From:", certificate.not_valid_before)
    print("Valid Until:", certificate.not_valid_after)
    print("Signature Algorithm:", certificate.signature_algorithm_oid)

def print_cert_subject(certificate):
    print("Subject:", certificate.subject.rfc4514_string())

def cert_subject_string(certificate):
    return certificate.subject.rfc4514_string()

def certificate_from_byte_array(certificate_bytes):
    return x509.load_pem_x509_certificate(certificate_bytes, default_backend())

def PEMcertificate_from_DER_byte_array(certificate_bytes):
    DER_certificate = x509.load_der_x509_certificate(certificate_bytes,default_backend())
    PEM_certificate_bytes = DER_certificate.public_bytes(encoding=serialization.Encoding.PEM)
    PEM_certificate = x509.load_pem_x509_certificate(PEM_certificate_bytes, default_backend())
    return PEM_certificate

def certificate_issuer_check(certificate,issuer_certificate):
    return check_signature(certificate.signature,certificate.tbs_certificate_bytes,issuer_certificate)

def certificate_date_check(certificate):
    try:
        not_before = certificate.not_valid_before
        not_after = certificate.not_valid_after
        current_date = datetime.utcnow()
        if current_date < not_before:
            # print("The certificate is not yet valid.")
            return False
        elif current_date > not_after:
            # print("The certificate is expired.")
            return False
        else:
            # print("The certificate is valid!")
            return True
    except Exception as e:
        print("Error:",e)
        return False

def check_signature(signed_bytes,original_byte_array,certificate):
    try:
        public_key = certificate.public_key()
        public_key.verify(
                signed_bytes,
                original_byte_array,
                padding.PKCS1v15(),
                hashes.SHA256()
        )
        return True
    except InvalidSignature:
        print("Invalid signature!")
        return False
    except Exception as e:
        print("Error:",e)
        return False

# alias of check_signature
def verify_signature(a,b,c):
    return check_signature(a,b,c)

def sign_byte_array_with_private(byte_array,private_key):
    signature = private_key.sign(
            byte_array,
            padding.PKCS1v15(),
            hashes.SHA256()
            )
    return signature

def encrypt_byte_array_with_public(byte_array,certificate):
    try:
        
        # print("Encryption function enter!")
        public_key = certificate.public_key()
        # debug_pub_crypto_attributes(public_key)

        # Check RFC 3447 section 7.1.1
        # https://datatracker.ietf.org/doc/html/rfc3447.html#section-7.1.1
        block_size = 190

        print(f"{ORANGE}The ENCRYPT block size is {block_size} bytes.{RESET}")
        
        enc_array = bytearray()
        input_offset = 0

        while input_offset < len(byte_array):
            input_block = byte_array[input_offset:input_offset + block_size]
            encrypted_block = public_key.encrypt(
                bytes(input_block),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                    )
                )
            enc_array.extend(encrypted_block)
            input_offset += block_size

        return enc_array
    except Exception as e:
        print("Encryption error:",e)
        traceback.print_exc()
        return None

def decrypt_byte_array_with_private(byte_array,private_key):
    try:
        
        # Check RFC 3447 section 7.1.2
        # https://datatracker.ietf.org/doc/html/rfc3447.html#section-7.1.2
        block_size = private_key.key_size // 8

        print(f"{ORANGE}The DECRYPT block size is {block_size} bytes.{RESET}")

        dec_array = bytearray()
        input_offset = 0
        
        while input_offset < len(byte_array):
            input_block = byte_array[input_offset:input_offset + block_size]
            decrypted_block = private_key.decrypt(
                    bytes(input_block),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                        )
                )
            dec_array.extend(decrypted_block)
            input_offset += block_size

        return dec_array
    except Exception as e:
        print("Decryption error:",e)
        return None

def debug_pub_crypto_attributes(public_key):
    print("Public Key:", public_key)
    print("Public Key Attributes:", dir(public_key))
    print("RSA Key Size:", public_key.key_size)
    print("MGF:", padding.MGF1(algorithm=hashes.SHA256()))
    print("Algorithm:", hashes.SHA256())
    
def debug_fun():
    try:
        read_CA_certificate_from_file()
        print(f"{YELLOW}CA certificate details:{RESET}")
        print_cert_details(CA_CERTIFICATE)
        print(f"{YELLOW}Checking that nodeA certificate is signed by CA certificate after reading it from filesystem:{RESET}")
        nodeA_cert = read_certificate_from_file("../rsa_creds/rsa_nodeA_certificate.crt")
        print_cert_details(nodeA_cert)
        if( certificate_issuer_check(nodeA_cert,CA_CERTIFICATE) ):
            print (f"{GREEN}The certificate of nodeA is signed by the CA!{RESET}")
        else:
            print(f"{RED}The certificate of nodeA is NOT signed by the CA!{RESET}")
        if( certificate_date_check(nodeA_cert) ):
            print (f"{GREEN}nodeA's certificate period is valid!{RESET}")
        else:
            print (f"{RED}The certificate's period is NOT valid!{RESET}")
    except FileNotFoundError:
        print(f"File not found error! {PATH_TO_CA_CERT}")
    except Exception as e:
        print("Error:",e)

def debug_fun2():
    try:
        global CA_CERTIFICATE
        global CA_PRIVATE
        read_CA_certificate_from_file()
        print(f"{YELLOW}CA certificate details:{RESET}")
        print_cert_details(CA_CERTIFICATE)
        read_CA_private_from_file()

        data_to_sign = os.urandom(32)

        signature = CA_PRIVATE.sign(
                data_to_sign,
                padding.PKCS1v15(),
                hashes.SHA256()
                )

        public_key = CA_CERTIFICATE.public_key()
        
        public_key.verify(
                signature,
                data_to_sign,
                padding.PKCS1v15(),
                hashes.SHA256()
                )
        print("Singature is valid!")

        print(f"{YELLOW}Now testing encrypt/decrypt{RESET}")

        # data = os.urandom(100000)
        data = os.urandom(8)
        print("The size of the initial data array is " + str(len(data)) )
    
        enc_array = encrypt_byte_array_with_public(data,CA_CERTIFICATE)
        
        if enc_array == None:
            print(f"{RED}Encryption failed!{RESET}")
            return
        else:
            print(f"{GREEN}Encryption successful!{RESET}")

        print("The size of the encrypted array is " + str(len(enc_array)) )

        dec_array = decrypt_byte_array_with_private(enc_array,CA_PRIVATE)

        if dec_array == None:
            print(f"{RED}Decryption failed!{RESET}")
            return
        else:
            print(f"{GREEN}Decryption successful!{RESET}")

        print("The size of the decrypted array is " + str(len(dec_array)) )

        if data == dec_array:
            print(f"{GREEN}Encryption and Decryption work!{RESET}")
        else:
            print(f"{RED}Problem with enc & dec{RESET}")

    except Exception as e:
        print("Error:",e)
        traceback.print_exc()

if __name__ == "__main__":
    init(autoreset=True)
    debug_fun()
    debug_fun2()
