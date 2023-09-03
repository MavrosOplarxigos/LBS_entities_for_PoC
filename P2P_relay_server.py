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
P2P_CERTIFICATE = retrieve_CA_certificate()
P2P_PRIVATE = retrieved_CA_private()
AVAILABILITY_RECORD_EXPIRATION_SECONDS = 120
AVAILABILITY_LIST_REFRESH_SECONDS = 60

# Serving Nodes List
# TODO: IMPROVEMENT: make this into a dictionary (or set like) for lower complexity (higher performance)
SERVING_NODE_LIST = []
SERVING_NODE_LIST_LOCK = threading.Lock()

# ServingNodeDict (IP address, port, timestamp) class used to "pack" a serving node record's data
class ServingNodeDict(dict):
    def __init__(self,serving_name,serving_ip,serving_port,record_timestamp):
        super().__init__()
        self['name'] = serving_name # The subject name in the certificate
        self['ip'] = serving_ip # The IP address as an integer 4 bytes
        self['port'] = serving_port # The serving ports as integer 4 bytes
        self['timestamp'] = record_timestamp # The timestamp is based on the time.time() not the crypto one since the usage here is just for record freshness

# This function returns the number of records that will be returned to the querying node
# The purpose of using a function for this is code modularity. Thus allowing us to make 
# dynamic choices every time (e.g. 5 to 10 records per query), or based on some metric
# related to a certain node (e.g. reputation, querying frequency).
def records_to_return():
    choice = 2
    # We can't send more than we have
    num_of_records = 0
    global SERVING_NODE_LIST_LOCK
    with SERVING_NODE_LIST_LOCK:
        num_of_records = min(choice,len(SERVING_NODE_LIST))
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
        if hello_string != b"HELLO":
            print(f"{RED}Expected CLIENT HELLO but the HELLO identifier prefix wasn't received. Instead we received: {hello_string}{RESET}")
            return None
        print("HELLO prefix received as expected.")

        # Receive [ClientCertificateLength] (4 bytes, big-endian)
        client_cert_len_data = receive_all(client_socket, 4)
        ClientCertificateLength = struct.unpack('>I', client_cert_len_data)[0]

        print(f"ClientCertificateLength is {ClientCertificateLength} bytes.")

        # Receive [ClientCertificateBytes]
        ClientCertificateBytes = receive_all(client_socket, ClientCertificateLength)
        # The Android .getEncoded function returns a DER format of the certificate
        client_certificate =  PEMcertificate_from_DER_byte_array(ClientCertificateBytes) 
        subject_name = client_certificate.subject.rfc4514_string()

        print(f"Certificate received with subject name = {subject_name}")

        # Receive [Timestamp] (8 bytes, big-endian)
        timestamp_data = receive_all(client_socket, 8)
        Timestamp = struct.unpack('>Q', timestamp_data)[0]

        print(f"The Timestamp is = {Timestamp}")

        # Verify the timestamp is fresh
        is_timestamp_fresh = verify_timestamp_freshness(Timestamp)
        if not is_timestamp_fresh:
            print(f"{RED}Expired timestamp received!{RESET}")
            return None

        # Receive [SignedTimestampLength]
        signed_timestamp_len_data = receive_all(client_socket, 4)
        SignedTimestampLength = struct.unpack('>I', signed_timestamp_len_data)[0]

        print(f"The length of the signed timestamp is {SignedTimestampLength}")

        # Receive [SignedTimestamp]
        SignedTimestamp = receive_all(client_socket, SignedTimestampLength)

        print(f"The SignedTimestamp was received!")

        # Verify the signature using the client certificate
        is_signature_valid = verify_signature(SignedTimestamp, timestamp_data, client_certificate)
        if not is_signature_valid:
            print(f"{RED}Invalid signature. Timestamp not signed correctly.{RESET}")
            return None

        # Verify that the certificate is signed by the CA
        #if client_certificate == None:
        #    print(f"{RED}IT IS THE CLIENT CERTIFICATE THAT IS NONE{RESET}")
        #if P2P_CERTIFICATE == None:
        #    print(f"{RED}IT IS THE P2P CERTIFICATE THAT IS NONE{RESET}")
        
        is_CA_signed = certificate_issuer_check(client_certificate, P2P_CERTIFICATE)
        if not is_CA_signed:
            print(f"{RED}Provided certificate is not signed by the CA.{RESET}")
            return None

        print(f"{GREEN}Client Hello message successfully received and verified from: {subject_name} / {client_address}.{RESET}")
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

# Function to retrieve the encrypted and signed availability disclosure from a node
# @ params client_socket The socket to talk to
# @ params client_address For debugging messages
# @ params node_cert The certificate to check the signature of the data with
# @ returns ServingNodeDict object constructed from received data to be added in the SERVING_NODE_LIST
def get_client_availability(client_socket, client_address, node_cert):

    # [ EDISCLOSURE LEN ] | [    EDISCLOSURE  ] | [ TIMESTAMP ] | [ SIGNED TIMESTAMP LEN ] | [    SIGNED TIMESTAMP     ]
    # [       4         ] | [ EDISCLOSURE LEN ] | [     8     ] | [          4           ] | [ SIGNED TIMESTAMP LENGTH ]

    EncDisclosureLengthBytes = receive_all(client_socket,4)
    EncDisclosureLength = struct.unpack('>I', EncDisclosureLengthBytes)[0]
    
    print(f"Encrypted disclosure length = {EncDisclosureLength}")

    EncDisclosureBytes = receive_all(client_socket,EncDisclosureLength)
    Disclosure = decrypt_byte_array_with_private(EncDisclosureBytes,P2P_PRIVATE)
    
    DiscIPInteger = struct.unpack('>I',Disclosure[0:4])[0]
    DiscPortInteger = struct.unpack('>I',Disclosure[4:])[0]
    DiscIP = socket.inet_ntoa(socket.inet_aton(str(DiscIPInteger)))

    print(f"Disclosure: {DiscIP}:{DiscPortInteger}")

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
    is_signature_valid = verify_signature(SignedTimestamp, timestamp_data, node_cert)
    if not is_signature_valid:
        print(f"{RED}Invalid signature. Timestamp not signed correctly.{RESET}")
        return None

    # Verify that the certificate is signed by the CA
    # if node_cert == None:
    #    print(

    is_CA_signed = certificate_issuer_check(node_cert,P2P_CERTIFICATE)
    if not is_CA_signed:
        print(f"{RED}Provided certificate is not signed by the CA.{RESET}")
        return None

    print(f"{GREEN}Disclosure timestamp passed!{RESET}")

    # Now we want to create the ServingNodeDict instance

    name_field = node_cert.subject.rfc4514_string()
    ip_field = DiscIP
    port_field = DiscPortInteger
    timestamp_field = time.time()

    print(f"{GREEN}Disclosure from {client_address}:{name_field} received successfully{RESET}")

    result = ServingNodeDict(name_field,ip_field,port_field,timestamp_field)
    return result

# Function to handle socket after accepting connection from a AVAILABILITY client
# @ params client_socket The socket to talk with
# @ params client_address The address of the client to debug
# returns Nothing. It is fully responsible to handle the connection.
def handle_availability_client(client_socket, client_address):

    print(f"{YELLOW}New availability disclosure from {client_address}{RESET}")

    # client hello to get the node's certificate
    node_cert = client_hello(client_socket, client_address)

    if(node_cert == None):
        print(f"{RED}Error: Availability server received an invalid Client Hello from {client_address}{RESET}")
        return
    
    # get the node availability
    node_availability_record = get_client_availability(client_socket, client_address, node_cert)
    
    if(node_availability_record == None):
        print(f"{RED}Error: Availability server received an invalid availability record from {client_address}{RESET}")
        return

    global SERVING_NODE_LIST_LOCK
    with SERVING_NODE_LIST_LOCK:
        global SERVING_NODE_LIST
        # delete any previous records in the list of the node (since they are now deprecated)
        SERVING_NODE_LIST = [node for node in SERVING_NODE_LIST if node['name'] != node_availability_record['name'] ]
        # add the new availability record to the global list
        SERVING_NODE_LIST.append(node_availability_record)

    return

# Function to handle socket after accepting connection form QUERY client
# @ params client_socket The socket to talk with
# @ params client_address The address of the client to debug
# returns Nothing. It is fully responsible to handle the connection.
def handle_query_client(client_socket, client_address):


    pass

# Function to manage the list and remove stale entries
def list_manager():
    global SERVING_NODE_LIST
    while True:
        # Remove entries older than 2 minutes
        current_time = time.time()
        SERVING_NODE_LIST = [node for node in SERVING_NODE_LIST if (current_time - node['timestamp'] <= AVAILABILITY_RECORD_EXPIRATION_SECONDS) ]
        time.sleep(AVAILABILITY_LIST_REFRESH_SECONDS)

def accept_query_client(query_server_socket):
    while True:
        query_client_socket, query_client_address = query_server_socket.accept()
        query_client_handle_thread = threading.Thread(target=handle_quering_client, args=(query_client_socket, query_client_address))
        query_client_handle_thread.start()
    pass

def accept_availability_client(availability_server_socket):
    while True:
        print(f"{YELLOW}accept_availability_client waiting for connection from some node...{RESET}\n",flush=True)
        availability_client_socket, availability_client_address = availability_server_socket.accept()
        print(f"{GREEN}accept_availability_client received connection from some node...{RESET}",flush=True)
        availability_client_handle_thread = threading.Thread(target=handle_availability_client, args=(availability_client_socket, availability_client_address))
        availability_client_handle_thread.start()
    pass

def sync_P2P_ntp():
    # Tell the ntp_helpers module to sync with the NTP server for timestamp checking
    print("P2P: NTP sync in progress...")
    ntp_sync()
    print(f"{GREEN}NTP sync completed!{RESET}")

def P2Pstarter():

    sync_P2P_ntp()
    
    # TCP/IP SOCKETS INITIALIZATION

    # Starting socket for QUERYING SERVER (i.e. the server that a node quries to discover other peers)
    print("P2P: QUERY server initiating...")
    query_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    query_server_address = ('localhost', QUERY_SERVER_PORT)
    query_server_socket.bind(query_server_address)
    query_server_socket.listen(MAX_QUERY_SERVER_CONNECTIONS)
    # print(f"{GREEN}P2P: QUERY server ready & listening!{RESET}")

    # Starting socket for AVAILABILITY SERVER (i.e. the server that a node solicits its availability to)
    print("P2P: AVAILABILITY server initiating...",flush=True)
    availability_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    availability_server_address = (physical_ethernet_address(), AVAILABILITY_SERVER_PORT)
    debug_availability_server_address = (physical_ethernet_address(), AVAILABILITY_SERVER_PORT)
    availability_server_socket.bind(availability_server_address)
    availability_server_socket.listen(MAX_AVAILABILITY_SERVER_CONNECTIONS)
    debug_ip_address_availability_server = socket.gethostbyname(availability_server_address[0])
    # print(f"{GREEN}P2P: AVAILABILITY server ready & listening!{RESET}",flush=True)
    print(f"{YELLOW}Availability Server On: {debug_ip_address_availability_server}:{debug_availability_server_address[1]}{RESET}")

    # THREADS INITIALIZATION

    # Start the LIST MANAGER thread (thread for updating the list of available peers)
    print("P2P: LIST MANAGER thread initiating...")
    list_manager_thread = threading.Thread(target=list_manager)
    list_manager_thread.daemon = True
    list_manager_thread.start()
    print(f"{GREEN}P2P: LIST MANAGER thread started!{RESET}")

    # Starting QUERY SERVER accept thread
    print("P2P: QUERY server connection accepting thread initiating...")
    query_server_thread = threading.Thread(target=accept_query_client, args=(query_server_socket,))
    query_server_thread.daemon = True
    query_server_thread.start()
    print(f"{GREEN}P2P: QUERY server connection accepting thread started!{RESET}")

    # Starting AVAILABILITY SERVER accept thread
    print("P2P: AVAILABILITY server connection accepting thread initiating...",flush=True)
    availability_server_thread = threading.Thread(target=accept_availability_client, args=(availability_server_socket,))
    availability_server_thread.daemon = True
    availability_server_thread.start()
    print(f"{GREEN}P2P: AVAILABILITY server connection accepting thread started!{RESET}",flush=True)

def P2Pmain():

    # Tell the ntp_helpers module to sync with the NTP server for timestamp checking
    print("NTP sync in progress...")
    ntp_sync()
    print(f"{GREEN}NTP sync completed!{RESET}")

    # Read CA credentials
    print("Retrieving CA credentials...")
    read_CA_private_from_file()
    read_CA_certificate_from_file()
    print(f"{GREEN}CA credentials retrieved!{RESET}")

    P2Pstarter()

if __name__ == "__main__":
    P2Pmain()

# client solicits to this server once he connects to it. This IP addresses along with 
# the ports will be saved in a list which I mention about below. The second thread will 
# be receiving in raw bytes from the client; that is an IP address and a port and this 
# will be saved in a list along with a timestamp that is the timestamp of the time that 
# they were written in the list. There will be a third thread that will be used for keeping 
#the contents of the list fresh; that is if an item on the list in more than 
# 2 minutes old it will be erased from the list.
