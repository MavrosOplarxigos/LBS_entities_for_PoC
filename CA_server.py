from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
import traceback
import os


PATH_TO_CA_CERT="../rsa_creds/rsa_CA_certificate.crt"
PATH_TO_CA_PRIVATE="../rsa_creds/rsa_CA_private.key"
CA_CERTIFICATE = None
CA_PRIVATE = None

# Colors for debugging
RESET = '\033[0m'
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'

def read_CA_private_from_file():
    global CA_PRIVATE
    with open(PATH_TO_CA_PRIVATE,"rb") as private_key_file:
        private_key_bytes = private_key_file.read()
        CA_PRIVATE = load_pem_private_key(private_key_bytes, password=None, backend=default_backend())

def read_certificate_from_file(path):
    with open(path,"rb") as cert_file:
        certificate_bytes = cert_file.read()
        return x509.load_pem_x509_certificate(certificate_bytes, default_backend())

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
        print ("Singature is valid!")

    except Exception as e:
        print("Error:",e)
        traceback.print_exc()


if __name__ == "__main__":
    debug_fun()
