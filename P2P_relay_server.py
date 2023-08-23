from tcp_helpers import *
from ntp_helpers import *
from CA_server import *
from debug_colors import *

import socket
import threading
import traceback
import struct
import time

# Configuration:
QUERY_SERVER_PORT = 50001
AVAILABILITY_SERVER_PORT = 50002
MAX_QUERY_SERVER_CONNECTIONS = 10
MAX_AVAILABILITY_SERVER_CONNECTIONS = 10
P2P_CERTIFICATE = CA_CERTIFICATE
P2P_PRIVATE = CA_PRIVATE

# Serving Nodes List
# IMPROVEMENT: make this into a dictionary (or set like) for lower complexity (higher performance)
serving_node_list = []

# ServingNodeDict (IP address, port, timestamp) class used to "pack" a serving node record's data
class ServingNodeDict(dict):
    def __init__(self,serving_name,serving_ip,serving_port,record_timestamp):
        super().__init__()
        self['name'] = serving_name # The subject name in the certificate
        self['ip'] = serving_ip
        self['port'] = serving_port
        self['timestamp'] = record_timestamp

# This function returns the number of records that will be returned to the querying node
# The purpose of using a function for this is code modularity. Thus allowing us to make 
# dynamic choices every time (e.g. 5 to 10 records per query), or based on some metric
# related to a certain node (e.g. reputation, querying frequency).
def records_to_return():
    choice = 2
    # We can't send more than we have
    num_of_records = min(choice,len(serving_node_list))
    return num_of_records

# Function to receive a CLIENT HELLO message of the format:
# [  HELLO  ] | [ClientCertificateLength] | [ClientCertificateBytes] | [Timestamp] | [SignedTimestampLength] | [SignedTimestamp]
# [ 5 bytes ] | [    4 bytes - integer  ] | [ variable # of bytes  ] | [ 8 bytes ] | [       4 bytes       ] | [ variable size ]
# @ params client_socket The socket to receive the data from
# @ params client_address The address of the client for debug messages
# @ returns x509 certificate of cryptography module
def client_hello(client_socket, client_address):
    try:
        print(f"Client Hello from {client_address}")

        # Receive the "HELLO" string bytes
        hello_string = receive_all(client_socket, 5)
        if hello_string != "HELLO":
            print(f"{RED}Expected CLIENT HELLO but the HELLO identifier prefix wasn't received.{RESET}")
            return None
        print("HELLO prefix received as expected.")

        # Receive [ClientCertificateLength] (4 bytes, big-endian)
        client_cert_len_data = receive_all(client_socket, 4)
        ClientCertificateLength = struct.unpack('>I', client_cert_len_data)[0]

        print(f"ClientCertificateLength is {ClientCertificateLength} bytes.")

        # Receive [ClientCertificateBytes]
        ClientCertificateBytes = receive_all(client_socket, ClientCertificateLength)
        client_certificate = certificate_from_byte_array(ClientCertificateBytes)
        subject_name = client_certificate.subject.rfc4514_string()

        print(f"Certificate received with subject name = {subject_name}")

        # Receive [Timestamp] (8 bytes, big-endian)
        timestamp_data = receive_all(client_socket, 8)
        Timestamp = struct.unpack('>Q', timestamp_data)[0]

        print(f"The Timestamp is = {Timestamp}")

        # Verify the timestamp is fresh
        is_timestamp_fresh = verify_timestamp_freshness(Timestamp)
        if not is_timestamp_fresh:
            print("{RED}Expired timestamp received!{RESET}")
            return None

        # Receive [SignedTimestampLength]
        signed_timestamp_len_data = receive_all(client_socket, 4)
        SignedTimestampLength = struct.unpack('>I', signed_timestamp_len_data)[0]

        print(f"The length of the signed timestamp is {SignedTimestampLength}")

        # Receive [SignedTimestamp]
        SignedTimestamp = receive_all(client_socket, SignedTimestampLength)

        print(f"The SignedTimestamp was received!")

        # Verify the signature using the client certificate
        is_signature_valid = verify_signature(Timestamp, SignedTimestamp, client_certificate)
        if not is_signature_valid:
            print("{RED}Invalid signature. Timestamp not signed correctly.{RESET}")
            return None

        # Verify that the certificate is signed by the CA
        is_CA_signed = certificate_issuer_check(client_certificate, CA_CERTIFICATE)
        if not is_CA_signed:
            print("{RED}Provided certificate is not signed by the CA.{RESET}")
            return None

        print(f"Client Hello message received and verified from: {subject_name} / {client_address}.")
        return client_certificate
    except Exception as e:
        print("Error CLIENT HELLO:",e)
        traceback.print_exc()
        return None

# Function to send a SERVER HELLO message of the format:
# [  HELLO  ] | [ServerCertificateLength] | [ServerCertificateBytes] | [Timestamp] | [SignedTimestampLength] | [SignedTimestamp]
# [ 5 bytes ] | [    4 bytes - integer  ] | [ variable # of bytes  ] | [ 8 bytes ] | [       4 bytes       ] | [ variable size ]
# @ params client_socket The socket to send data to
# @ params client_address The address of the client for debug messages
# @ returns True if successful, False otherwise
def server_hello(client_socket, client_address):
    try:
        
        hello_msg = b"HELLO"

        server_certificate_length_int = len(P2P_CERTIFICATE)
        ServerCertificateLenght = struct.pack('I',server_certificate_length_int)
                
        ServerCertificateBytes = P2P_CERTIFICATE.public_bytes(Encoding.PEM)

        timestamp_int = int(time.time() * 1000)
        Timestamp = struct.pack('Q',timesamp_int)

        SignedTimestamp = sign_byte_array_with_private(Timestamp,P2P_PRIVATE)
        signed_timestamp_length_int = len(SignedTimestamp)
        SingedTimestampLenght = struct.pack('I',signed_timestamp_length_int)

        server_hello_msg = (
                hello_msg +
                ServerCertificateLenght +
                ServerCertificateBytes +
                Timestamp +
                SignedTimestampLength +
                SignedTimestamp
                )

        send_all(client_socket,server_hello_msg)
        return True
    except Exception as e:
        print("Error on SERVER HELLO:",e)
        traceback.print_exc()
        return False

# Function to handle socket after accepting connection from a AVAILABILITY client
# @ params client_socket The socket to talk with
# @ params client_address The address of the client to debug
# returns Nothing. It is fully responsible to handle the connection.
def handle_availability_client(client_socket, client_address):



    pass

# Function to handle socket after accepting connection form QUERY client
# @ params client_socket The socket to talk with
# @ params client_address The address of the client to debug
# returns Nothing. It is fully responsible to handle the connection.
def handle_query_client(client_socket, client_address):



    pass

# Function to manage the list and remove stale entries
def list_manager():
    while True:
        # Remove entries older than 2 minutes from both lists
        current_time = time.time()
        client_data_list[:] = [item for item in client_data_list if current_time - item[1] <= 120]
        raw_data_list[:] = [item for item in raw_data_list if current_time - item[1] <= 120]
        time.sleep(60)  # Check every 60 seconds

def accept_query_client(query_server_socket):
    while True:
        query_client_socket, query_client_address = query_server_socket.accept()
        query_client_handle_thread = threading.Thread(target=handle_quering_client, args=(query_client_socket, query_client_address))
        query_client_handle_thread.start()
    pass

def accept_availability_client(availability_server_socket):
    while True:
        availability_client_socket, availability_client_address = availablity_server_socket.accept()
        availability_client_handle_thread = threading.Thread(target=handle_availability_client, args=(availability_client_socket, availability_client_address))
        availability_client_handle_thread.start()
    pass

def main():

    # Tell the ntp_helpers module to sync with the NTP server for timestamp checking
    print("NTP sync in progress...")
    ntp_sync()
    print(f"{GREEN}NTP sync completed!{RESET}")

    # Read CA credentials
    print("Retrieving CA credentials...")
    read_CA_private_from_file()
    read_CA_certificate_from_file()
    print(f"{GREEN}CA credentials retrieved!{RESET}")
    
    # TCP/IP SOCKETS INITIALIZATION

    # Starting socket for QUERYING SERVER (i.e. the server that a node quries to discover other peers)
    print("QUERY server initiating...")
    query_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    query_server_address = ('localhost', QUERY_SERVER_PORT)
    query_server_socket.bind(query_server_address)
    query_server_socket.listen(MAX_QUERY_SERVER_CONNECTIONS)
    print(f"{GREEN}QUERY server ready & listening!{RESET}")

    # Starting socket for AVAILABILITY SERVER (i.e. the server that a node solicits its availability to)
    print("AVAILABILITY server initiating...")
    availability_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    availability_server_address = ('localhost', AVAILABILITY_SERVER_PORT)
    availability_server_socket.bind(availability_server_address)
    availability_server_socket.listen(MAX_AVAILABILITY_SERVER_CONNECTIONS)
    print(f"{GREEN}AVAILABILITY server ready & listening!{RESET}")

    # THREADS INITIALIZATION

    # Start the LIST MANAGER thread (thread for updating the list of available peers)
    print("LIST MANAGER thread initiating...")
    list_manager_thread = threading.Thread(target=list_manager)
    list_manager_thread.daemon = True
    list_manager_thread.start()
    print(f"{GREEN}LIST MANAGER thread started!{RESET}")

    # Starting QUERY SERVER accept thread
    print("QUERY server connection accepting thread initiating...")
    query_server_thread = threading.Thread(target=accept_query_client, args=(query_server_socket))
    query_server_thread.start()
    print("{GREEN}QUERY server connection accepting thread started!{RESET}")

    # Starting AVAILABILITY SERVER accept thread
    print("AVAILABILITY server connection accepting thread initiating...")
    availability_server_thread = threading.Thread(target=accept_availability_client, args=(availability_server_socket))
    availabilit_server_thread.start()
    print("{GREEN}AVAILABILITY server connection accepting thread started!{RESET}")

if __name__ == "__main__":
    main()

# client solicits to this server once he connects to it. This IP addresses along with 
# the ports will be saved in a list which I mention about below. The second thread will 
# be receiving in raw bytes from the client; that is an IP address and a port and this 
# will be saved in a list along with a timestamp that is the timestamp of the time that 
# they were written in the list. There will be a third thread that will be used for keeping 
#the contents of the list fresh; that is if an item on the list in more than 
# 2 minutes old it will be erased from the list.
