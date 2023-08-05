from tcp_helpers import *
from ntp_helpers import *

import socket
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509

# Serving Nodes List
# IMPROVEMENT: make this into a dictionary (or set like) for lower complexity (higher performance)
serving_node_list = []

# ServingNodeDict (IP address, port, timestamp) class used to "pack" a serving node record's data
class ServingNodeDict(dict):
    def __init__(self,serving_ip,serving_port,record_timestamp):
        super().__init__()
        self['ip'] = serving_ip
        self['port'] = serving_port
        self['timestamp'] = record_timestamp

# This function returns the number of records that will be returned to the querying node
# The purpose of using a function for this is code modularity. Thus allowing us to make 
# dynamic choices everyt time (e.g. 5 to 10 records per query), or based on some metric
# related to a certain node (e.g. reputation, querying frequency).
def records_to_return():
    choice = 2
    # We can't send more than we have
    num_of_records = min(choice,len(serving_node_list))
    return num_of_records

# Function to receive a CLIENT HELLO message of the format:
# [ClientCertificateLength] | [ClientCertificateBytes] | [Timestamp] | [SignedTimestampLength] | [SignedTimestamp]
# @ params client_socket The socket to receive the data from
# @ params client_address The address of the client for output messages
# @ returns The certificate bytes
def client_hello(client_socket, client_address):

    print(f"Client Hello from {client_address}")

    # Receive [ClientCertificateLength] (4 bytes, big-endian)
    client_cert_len_data = receive_all(client_socket, 4)
    ClientCertificateLength = struct.unpack('>I', client_cert_len_data)[0]

    print(f"ClientCertificateLength is {ClientCertificateLength} bytes.")

    # Receive [ClientCertificateBytes]
    ClientCertificateBytes = receive_all(client_socket, ClientCertificateLength)
    certificate = x509.load_pem_x509_certificate(ClientCertificateBytes, default_backend())
    subject_name = certificate.subject.rfc4514_string()

    print(f"Certificate received with subject name = {subject_name}")

    # Receive [Timestamp] (8 bytes, big-endian)
    timestamp_data = receive_all(client_socket, 8)
    Timestamp = struct.unpack('>Q', timestamp_data)[0]

    # Receive [SignedTimestampLength]
    signed_timestamp_len_data = receive_all(client_socket, 4)
    SignedTimestampLength = struct.unpack('>I', signed_timestamp_len_data)[0]

    # Receive [SignedTimestamp]
    SignedTimestamp = receive_all(client_socket, SignedTimestampLength)

    # Verify the timestamp is fresh
    is_timestamp_fresh = verify_timestamp_freshness(Timestamp)

    # Verify the signature using the client certificate
    is_signature_valid = verify_signature(Timestamp, SignedTimestamp, ClientCertificateBytes)
    if not is_signature_valid:
        print("Invalid signature. Timestamp not signed correctly.")
        return None




    print("Client hello message received and verified.")
    return client_cert_bytes


# Querying Client
def handle_quering_client(client_socket, client_address):

    # Client Hello: Receive/Verify Client's certificate & timestamp
    client_certificat, is_message_valid = client_hello(client_socket, client_address)

    # Server Hello: Send Server's certificate & signed timestamp

    # Receive the client's query and process it

    # Step 1: Select at random some records from the serving node list

    # Step 2: Put the selected records into a single byte array with delimiter

    # Step 3: Encrypt the records byte array using the client's public key

    # Step 3: Encrypt the records byte array using the client's public key

    # Return to the querying client the encypted list along with a signed timestamp

    pass

# Function to handle client connections for the second server
def handle_raw_data_client(client_socket, client_address):
    # Receive raw bytes from the client (IP address, port) and timestamp
    # Add the raw data along with the timestamp to the raw_data_list
    pass

# Function to manage the list and remove stale entries
def list_manager():
    while True:
        # Remove entries older than 2 minutes from both lists
        current_time = time.time()
        client_data_list[:] = [item for item in client_data_list if current_time - item[1] <= 120]
        raw_data_list[:] = [item for item in raw_data_list if current_time - item[1] <= 120]
        time.sleep(60)  # Check every 60 seconds

def get_current_time(ntp_server='time.google.com'):
    try:
        # Create an NTP client instance
        client = ntplib.NTPClient()

        # Query the NTP server for the current time
        response = client.request(ntp_server)

        # Get the current time from the NTP response
        ntp_time = response.tx_time

        # Convert NTP time to a human-readable format
        current_time = ctime(ntp_time)

        return current_time
    except ntplib.NTPException as e:
        print(f"Failed to fetch time from NTP server: {e}")
        return None

def main():

    # Get current time


    # Read CA credentials
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Create sockets for two servers
    query_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    query_server_address = ('localhost', 8000)
    query_server_socket.bind(query_server_address)
    query_server_socket.listen(5)

    raw_data_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_data_server_address = ('localhost', 8001)
    raw_data_server_socket.bind(raw_data_server_address)
    raw_data_server_socket.listen(5)

    # Start the list manager thread
    list_manager_thread = threading.Thread(target=list_manager)
    list_manager_thread.daemon = True
    list_manager_thread.start()

    # Start the first server thread
    query_server_thread = threading.Thread(target=handle_query_client, args=(client_socket, client_address, public_key))
    query_server_thread.start()

    # Start the second server thread
    raw_data_server_thread = threading.Thread(target=handle_raw_data_client, args=(client_socket, client_address))
    raw_data_server_thread.start()

    while True:
        # Accept incoming connections for the first server
        query_client_socket, query_client_address = query_server_socket.accept()

        # Accept incoming connections for the second server
        raw_data_client_socket, raw_data_client_address = raw_data_server_socket.accept()

        # Handle each client connection in a separate thread
        query_server_thread = threading.Thread(target=handle_query_client, args=(query_client_socket, query_client_address, public_key))
        query_server_thread.start()

        raw_data_server_thread = threading.Thread(target=handle_raw_data_client, args=(raw_data_client_socket, raw_data_client_address))
        raw_data_server_thread.start()

if __name__ == "__main__":
    main()

# I want a program that has 2 TCP servers accepting connections in 2 separate ports
# at the same time using threads (each server has its own thread). The first thread 
# client solicits to this server once he connects to it. This IP addresses along with 
# the ports will be saved in a list which I mention about below. The second thread will 
# be receiving in raw bytes from the client; that is an IP address and a port and this 
# will be saved in a list along with a timestamp that is the timestamp of the time that 
# they were written in the list. There will be a third thread that will be used for keeping 
#the contents of the list fresh; that is if an item on the list in more than 
# 2 minutes old it will be erased from the list.
