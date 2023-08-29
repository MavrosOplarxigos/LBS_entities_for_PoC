# Usage: python pseudocreds_gen.py <name_of_node>
# the credentials will be saved in the ../rsa_creds directory
import os
import sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from CA_server import *
from colorama import init, Fore
from debug_colors import *

node_name = None

def exists_file(path):
    try:
        with open(path,"rb") as file_s:
            return True
    except Exception as e:
        return False

def generate_pseudonymous_certificates():
    for i in range(1, 5):

        subject_name = node_name + "_PSEUDO_" + str(i)
        path_to_Pcert = PATH_TO_CREDS + f"rsa_{node_name}_Pcert{i}.crt"
        path_to_Pprivate = PATH_TO_CREDS + f"rsa_{node_name}_Pprivate{i}.key"
        path_to_Pcsr = PATH_TO_CREDS + f"rsa_{node_name}_Pcsr{i}.csr"
        
        if exists_file(path_to_Pcert):
            print(f"{RED}The file {path_to_Pcert} already exists.{RESET}")
            continue

        os.system(f"openssl genpkey -algorithm RSA -out {path_to_Pprivate}")
        os.system(f"openssl req -new -key {path_to_Pprivate} -out {path_to_Pcsr} -subj '/CN={subject_name}'")
        os.system(f"openssl x509 -req -in {path_to_Pcsr} -CA {PATH_TO_CA_CERT} -CAkey {PATH_TO_CA_PRIVATE} -out {path_to_Pcert} -days 365")

        print(f"{GREEN}Generated {subject_name}!{RESET}")


def main():
    init(autoreset=True)
    global node_name
    if len(sys.argv) != 2:
        print("Usage: python pseudocreds_gen.py <name_of_node>")
        exit(0)
    else:
        node_name = str(sys.argv[1])
    if not exists_name(node_name):
        print(f"Name {node_name} doens't exist.")
        return
    print(f"Generating pseudonymous credentials for {node_name}")
    generate_pseudonymous_certificates()

if __name__ == "__main__":
    main()
