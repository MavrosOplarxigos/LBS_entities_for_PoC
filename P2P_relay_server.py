from tcp_helpers import *
from ntp_helpers import *
from CA_server import *
from debug_colors import *

import SharedVarsExperiment
import socket
import threading
import traceback
import struct
import time
import random

# Configuration:
QUERY_SERVER_PORT = 50001
AVAILABILITY_SERVER_PORT = 50002
MAX_QUERY_SERVER_CONNECTIONS = 10
MAX_AVAILABILITY_SERVER_CONNECTIONS = 10

P2P_CERTIFICATE = retrieve_CA_certificate()
P2P_PRIVATE = retrieved_CA_private()

AVAILABILITY_RECORD_EXPIRATION_SECONDS = 12
AVAILABILITY_LIST_REFRESH_SECONDS = 3 # we want to ensure fresh records but without the cost of performance
QUERY_MIN_INTERVAL_TOLERANCE_SECONDS = 5 # to avoid intentional flooding
QUERY_EARLY_INTERVAL_SECONDS = 10 # early query (that if justified is serviced)
QUERY_EARLY_MIN_FRESH_FOR_NOREPLY = 2 # if at least this number of records are still fresh according to our knowledge we won't answer the EARLY query

# IMPROVEMENT: make this into a dictionary (or set like) for lower complexity (higher performance?)
SERVING_NODE_LIST = []
SERVING_NODE_LIST_LOCK = threading.Lock()
QUERYING_NODE_LIST = []
QUERYING_NODE_LIST_LOCK = threading.Lock() # There can be multiple threads trying to change this like with the serving node list

# ServingNodeDict (IP address, port, timestamp) class used to "pack" a serving node record's data
class ServingNodeDict(dict):
    def __init__(self,serving_name,serving_ip,serving_port,record_timestamp):
        super().__init__()
        self['name'] = serving_name # The subject name in the certificate
        self['ip'] = serving_ip # The IP address as a string (for debugs). Converted to integer when sending it.
        self['port'] = serving_port # The serving ports as integer 4 bytes
        self['timestamp'] = record_timestamp # The timestamp is based on the time.time() not the crypto one since the usage here is just for record freshness

class QueryingNodeDict(dict):
    def __init__(self,querying_name,record_timestamp,records):
        super().__init__()
        self['name'] = querying_name
        self['timestamp'] = record_timestamp
        self['records'] = records # list of records we returned to it last time

# This function returns the number of records that will be returned to the querying node
# The purpose of using a function for this is code modularity. Thus allowing us to make 
# dynamic choices every time (e.g. 5 to 10 records per query), or based on some metric
# related to a certain node (e.g. reputation, querying frequency).
def records_to_return(my_name):
    # print(f"{MAGENTA}Records to acquire per query = {SharedVarsExperiment.RECORDS_TO_ACQUIRE_PER_QUERY}{RESET}",flush=True)
    choice = SharedVarsExperiment.RECORDS_TO_ACQUIRE_PER_QUERY
    # We can't send more than we have
    my_records = len([e for e in SERVING_NODE_LIST if e['name'] == my_name])
    num_of_records = min(choice,len(SERVING_NODE_LIST)-my_records)
    # print(f"{ORANGE}records to return for {my_name} are {num_of_records}{RESET}")
    return num_of_records

# Function to receive a CLIENT HELLO message of the format:
# [  HELLO  ] | [ClientCertificateLength] | [ClientCertificateBytes] | [Timestamp] | [SignedTimestampLength] | [SignedTimestamp]
# [ 5 bytes ] | [    4 bytes - integer  ] | [ variable # of bytes  ] | [ 8 bytes ] | [       4 bytes       ] | [ variable size ]
# @ params client_socket The socket to receive the data from
# @ params client_address The address of the client for debug messages
# @ returns x509 certificate of cryptography module
def client_hello(client_socket, client_address, is_availability):
    try:
        # print(f"Client Hello from {client_address}")

        # Receive the "HELLO" string bytes
        hello_string = receive_all(client_socket, 5)

        if hello_string != b"HELLO":
            print(f"{RED}Client Hello: Expected CLIENT HELLO but the HELLO identifier prefix wasn't received. Instead we received: {hello_string}{RESET}")
            return None
        # print("HELLO prefix received as expected.")

        # Receive [ClientCertificateLength] (4 bytes, big-endian)
        client_cert_len_data = receive_all(client_socket, 4)
        ClientCertificateLength = struct.unpack('>I', client_cert_len_data)[0]

        # print(f"ClientCertificateLength is {ClientCertificateLength} bytes.")

        # Receive [ClientCertificateBytes]
        ClientCertificateBytes = receive_all(client_socket, ClientCertificateLength)
        # The Android .getEncoded function returns a DER format of the certificate
        client_certificate =  PEMcertificate_from_DER_byte_array(ClientCertificateBytes) 
        subject_name = client_certificate.subject.rfc4514_string()

        # print(f"Certificate received with subject name = {subject_name}")

        # Receive [Timestamp] (8 bytes, big-endian)
        timestamp_data = receive_all(client_socket, 8)
        Timestamp = struct.unpack('>Q', timestamp_data)[0]

        # print(f"The Timestamp is = {Timestamp}")

        # Verify the timestamp is fresh
        is_timestamp_fresh = verify_timestamp_freshness(Timestamp)
        if not is_timestamp_fresh:
            print(f"{RED}Client Hello: Expired timestamp received!{RESET}")
            return None

        # Receive [SignedTimestampLength]
        signed_timestamp_len_data = receive_all(client_socket, 4)
        SignedTimestampLength = struct.unpack('>I', signed_timestamp_len_data)[0]

        # print(f"The length of the signed timestamp is {SignedTimestampLength}")

        # Receive [SignedTimestamp]
        SignedTimestamp = receive_all(client_socket, SignedTimestampLength)

        # print(f"The SignedTimestamp was received!")

        # Verify the signature using the client certificate
        is_signature_valid = verify_signature(SignedTimestamp, timestamp_data, client_certificate)
        if not is_signature_valid:
            print(f"{RED}Client Hello: Invalid signature. Timestamp not signed correctly.{RESET}")
            return None

        # Verify that the certificate is signed by the CA
        #if client_certificate == None:
        #    print(f"{RED}IT IS THE CLIENT CERTIFICATE THAT IS NONE{RESET}")
        #if P2P_CERTIFICATE == None:
        #    print(f"{RED}IT IS THE P2P CERTIFICATE THAT IS NONE{RESET}")
        
        is_CA_signed = certificate_issuer_check(client_certificate, P2P_CERTIFICATE)
        if not is_CA_signed:
            print(f"{RED}Client Hello: Provided certificate is not signed by the CA.{RESET}")
            return None

        # print(f"{GREEN}Client Hello message successfully received and verified from: {subject_name} / {client_address}.{RESET}")
        if not is_availability:
            return client_certificate
        else:
            return (client_certificate,timestamp_data)
    except Exception as e:
        print("Error CLIENT HELLO:",e)
        traceback.print_exc()
        return None

# DEPRECATED (because we don't need to send server hello if the P2PCertificate is the same as the CA certificate)
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
def get_client_availability(client_socket, client_address, node_cert, timestamp_data):

    # [ EDISCLOSURE LEN ] | [    EDISCLOSURE  ] | [ TIMESTAMP ] | [ SIGNED TIMESTAMP LEN ] | [    SIGNED TIMESTAMP     ]
    # [       4         ] | [ EDISCLOSURE LEN ] | [     8     ] | [          4           ] | [ SIGNED TIMESTAMP LENGTH ]

    # changed to:

    # [ EDISCLOSURE LEN ] | [    EDISCLOSURE  ] | [ SIGNED DISCLOSURE || timestamp LEN ] | [    SIGNED DISCLOSURE                  ]
    # [       4         ] | [ EDISCLOSURE LEN ] | [          4                         ] | [ SIGNED DISCLOSURE || timestamp LENGTH ]

    EncDisclosureLengthBytes = receive_all(client_socket,4)
    EncDisclosureLength = struct.unpack('>I', EncDisclosureLengthBytes)[0]
    
    # print(f"Encrypted disclosure length = {EncDisclosureLength}")

    EncDisclosureBytes = receive_all(client_socket,EncDisclosureLength)
    Disclosure = decrypt_byte_array_with_private(EncDisclosureBytes,P2P_PRIVATE)
    
    DiscIPInteger = struct.unpack('>I',Disclosure[0:4])[0]
    DiscPortInteger = struct.unpack('>I',Disclosure[4:])[0]
    DiscIP = socket.inet_ntoa(socket.inet_aton(str(DiscIPInteger)))

    # print(f"Disclosure: {DiscIP}:{DiscPortInteger}")

    # Receive [Timestamp] (8 bytes, big-endian)
    # timestamp_data = receive_all(client_socket, 8)
    # Timestamp = struct.unpack('>Q', timestamp_data)[0]
    # print(f"The Timestamp is = {Timestamp}")
    # Verify the timestamp is fresh
    # is_timestamp_fresh = verify_timestamp_freshness(Timestamp)
    # if not is_timestamp_fresh:
    #    print("{RED}Expired timestamp received on client_availability from {DiscIP}!{RESET}")
    #    return None
    # Receive [SignedTimestampLength]
    # signed_timestamp_len_data = receive_all(client_socket, 4)
    # SignedTimestampLength = struct.unpack('>I', signed_timestamp_len_data)[0]
    # print(f"The length of the signed timestamp is {SignedTimestampLength}")
    # Receive [SignedTimestamp]
    # SignedTimestamp = receive_all(client_socket, SignedTimestampLength)
    # print(f"The SignedTimestamp was received!")
    # Verify the signature using the client certificate
    # is_signature_valid = verify_signature(SignedTimestamp, timestamp_data, node_cert)
    # if not is_signature_valid:
    #    print(f"{RED}Invalid signature. Timestamp not signed correctly.{RESET}")
    #    return None

    # Verify that the certificate is signed by the CA
    is_CA_signed = certificate_issuer_check(node_cert,P2P_CERTIFICATE)
    if not is_CA_signed:
        print(f"{RED}Provided certificate is not signed by the CA.{RESET}")
        return None

    # Receive & check signed disclosure
    SignedDisclosureLengthBytes = receive_all(client_socket,4)
    SignedDisclosureLength = struct.unpack('>I', SignedDisclosureLengthBytes)[0]
    SignedDisclosureBytes = receive_all(client_socket,SignedDisclosureLength)
    concatenation = timestamp_data + Disclosure

    # here we want to concatenate the timestamp_data with the Disclosure to get the signature right
    is_signature_valid = verify_signature(SignedDisclosureBytes,concatenation,node_cert)

    # Now we want to create the ServingNodeDict instance
    name_field = node_cert.subject.rfc4514_string()

    if not is_signature_valid:
        print(f"{RED}Invalid disclosure signature from " + name_to_CN_only(name_field) + f"{RESET}")
        return None

    ip_field = DiscIP
    port_field = DiscPortInteger
    timestamp_field = time.time()

    result = ServingNodeDict(name_field,ip_field,port_field,timestamp_field)
    # print(f"{GREEN}Disclosure from {client_address}:" + name_to_CN_only(name_field) + f" received successfully:\n{result}{RESET}",flush=True)

    return result

# Function to handle socket after accepting connection from a AVAILABILITY client
# @ params client_socket The socket to talk with
# @ params client_address The address of the client to debug
# returns Nothing. It is fully responsible to handle the connection.
def handle_availability_client(client_socket, client_address):

    # print(f"{YELLOW}New availability disclosure from {client_address}{RESET}",flush=True)

    # client hello to get the node's certificate
    node_cert, timestamp_data = client_hello(client_socket, client_address, True)

    if(node_cert == None):
        print(f"{RED}Error: Availability server received an invalid Client Hello from {client_address}{RESET}")
        client_socket.close()
        return
    
    # get the node availability
    node_availability_record = get_client_availability(client_socket, client_address, node_cert, timestamp_data)
    
    if(node_availability_record == None):
        print(f"{RED}Error: Availability server received an invalid availability record from {client_address}{RESET}")
        client_socket.close()
        return

    global SERVING_NODE_LIST_LOCK
    with SERVING_NODE_LIST_LOCK:
        global SERVING_NODE_LIST
        # delete any previous records in the list of the node (since they are now deprecated)
        SERVING_NODE_LIST = [node for node in SERVING_NODE_LIST if node['name'] != node_availability_record['name'] ]
        # add the new availability record to the global list
        SERVING_NODE_LIST.append(node_availability_record)

    client_socket.close()
    return

# Function to return serving records list

def give_me_SERVING_records(my_name):
    with SERVING_NODE_LIST_LOCK:
        goal_size = records_to_return(my_name)
        eligible_positions = [i for i, node in enumerate(SERVING_NODE_LIST) if node['name'] != my_name ]
        goal_size = min(goal_size,len(eligible_positions))
        random_positions = random.sample(eligible_positions,goal_size)
        actual_records_to_return = [ SERVING_NODE_LIST[i] for i in random_positions ]
        # print(f"{ORANGE}Serving records to return =  {actual_records_to_return}{RESET}")
        return actual_records_to_return 

# Function to send the serving node records as a response to the client
# @ params records The list with the records to repsond with
# @ params client_socket The socket to output to
# @ params client_address For debugging
# @ params client_certificate For crypto
def send_query_records(records,client_socket,client_address,client_certificate):

    node_name = client_certificate.subject.rfc4514_string()
    
    if( records == None or len(records) == 0 ):
        emptyr_msg = b"EMPTYR"
        send_all(client_socket,emptyr_msg)
        print( f"{RED}We have NO RECORDS to share with {client_address} aka " + name_to_CN_only(node_name) + f"{RESET}" )
        return

    okrecv_msg = b"OKRECV" # prefix to the byte array to send to show to the client that indeed records will be returned
    
    debug_str = f"{GREEN}Sent to {client_address} aka " + name_to_CN_only(node_name) + " the following records:\n"

    debug_str = "NUMBER_OF_RECORDS = " + str(len(records)) + "\n"
    
    number_of_records_field = struct.pack('<I',len(records))
    
    records_byte_array = []
    for rec in records:
        debug_str += str(rec['ip']) + ":" + str(rec['port']) + ",\n"
        records_byte_array += struct.pack('<I', IP_TO_INT(rec['ip']) )
        records_byte_array += struct.pack('<I',int(rec['port']))
    debug_str += "DEC_RECORDS_BYTE_ARRAY_SIZE = " + str(len(records_byte_array)) + "\n"
    debug_str += f"DEC_RECORDS_BYTE_ARRAY = {records_byte_array} \n"
    records_byte_array = bytes(records_byte_array)

    Original_Length = len(records_byte_array)
    Original_Length_byte_array = struct.pack('<I',Original_Length)

    untouched_ENC_records_byte_array = encrypt_byte_array_with_public(records_byte_array,client_certificate)
    ENC_records_byte_array = bytes( [ byte for byte in untouched_ENC_records_byte_array ] )
    debug_ENC_records = [ byte for byte in untouched_ENC_records_byte_array ]

    if ENC_records_byte_array != untouched_ENC_records_byte_array:
        print(f"{RED}IMPOSSIBLE!{RESET}")

    len_for_debug = len(ENC_records_byte_array)
    debug_str += f"ENC_BYTE_ARRAY_LEN = {len_for_debug} \n"
    debug_str += f"ENC_BYTE_ARRAY = {debug_ENC_records} \n"

    ENC_records_byte_array_len = struct.pack('<I',len(ENC_records_byte_array))
    
    debug_str += f"{RESET}"
    
    # [NUMBER OF RECORDS] | 
    # [       4         ] | 

    response = (
            okrecv_msg +
            number_of_records_field +
            ENC_records_byte_array_len +
            ENC_records_byte_array +
            Original_Length_byte_array
            )

    send_all(client_socket,response)
    # print(debug_str)
    return

# Function to handle socket after accepting connection from QUERY client
# @ params client_socket The socket to talk with
# @ params client_address The address of the client to debug
# returns Nothing. It is fully responsible to handle the connection.
def handle_query_client(client_socket, client_address):

    # print(f"{YELLOW}New peer discovery query from {client_address}{RESET}",flush=True)

    # client_hello to get the node's certificate
    node_cert = client_hello(client_socket, client_address, False)

    if(node_cert == None):
        print(f"{RED}Error: Peer discovery server received an invalid Client Hello from {client_address}{RESET}")
        return

    name_field = node_cert.subject.rfc4514_string()

    global QUERYING_NODE_LIST
    global QUERYING_NODE_LIST_LOCK

    with QUERYING_NODE_LIST_LOCK:
        
        # retrieve the last query record from the client
        query_node_list_record = [e for e in QUERYING_NODE_LIST if e['name'] == name_field]

        if( len(query_node_list_record) == 0 ):
            # first time
            records = give_me_SERVING_records(name_field)
            # save these records for expiration validation on possible future early requests
            my_query_node_record = QueryingNodeDict(name_field,time.time(),records)
            QUERYING_NODE_LIST.append(my_query_node_record)
            # OK now we can send the reply
            print(f"{ORANGE}First time records to send: {records} {RESET}")
            send_query_records(records,client_socket,client_address,node_cert)
        else:
            prev = query_node_list_record[0]

            # TODO: Add check that the querying node has registered itself in the availability list

            # check if the query is too frequent
            if( ((time.time()) - prev['timestamp'] < QUERY_MIN_INTERVAL_TOLERANCE_SECONDS) and (SharedVarsExperiment.OVERRIDE_AVAILABILITY_CHECKS_ON_EARLY_REASKS == 0) ):
                # too frequent requests
                too_freq_msg = b"TOOFRQ"
                send_all(client_socket,too_freq_msg)
                print("{RED}{name_field} @ {client_address} has requested PEERS too frequently!{RESET}")
                client_socket.close()
                return

            # check if the request is not early
            if( ((time.time()) - prev['timestamp'] >= QUERY_EARLY_INTERVAL_SECONDS) or (SharedVarsExperiment.OVERRIDE_AVAILABILITY_CHECKS_ON_EARLY_REASKS == 1) ):
                # normal request as expected
                records = give_me_SERVING_records(name_field)
                # delete previous QUERYING_NODE_LIST record
                QUERYING_NODE_LIST = [node for node in QUERYING_NODE_LIST if node['name'] != name_field ]
                # add the new QUERY records for the client
                my_query_node_record = QueryingNodeDict(name_field,time.time(),records)
                QUERYING_NODE_LIST.append(my_query_node_record)
                # OK now send the reply back
                print(f"{ORANGE}Normal time records to send: {records} {RESET}")
                send_query_records(records,client_socket,client_address,node_cert)
            else:
                # early request check if it makes sense (i.e. the records we sent last time are no longer in the serving list or are not fresh)
                with SERVING_NODE_LIST_LOCK:
                    commons = [ node for node in prev['records'] if node in SERVING_NODE_LIST ]
                    commons_fresh_ones = 0
                    current_time = time.time()
                    for node in commons:
                        if current_time - node['timestamp'] <= AVAILABILITY_RECORD_EXPIRATION_SECONDS:
                            commons_fresh_ones+=1

                    if commons_fresh_ones >= QUERY_EARLY_MIN_FRESH_FOR_NOREPLY:
                        too_freq_msg = b"EINVLD" # Early and invalid
                        send_all(client_socket,too_freq_msg)
                        print(f"{RED}Early request from {name_field} @ {client_address} rejected since {commons_fresh_ones} of the PEERS we last gave to it are still fresh{RESET}")
                        client_socket.close()
                        return

                # if we are here that means the EARLY query will be serviced
                print(f"{GREEN}Early request from {name_field} @ {client_address} validated and accepted!{RESET}")
                records = give_me_SERVING_records(name_field)
                # delete previous QUERYING_NODE_LIST record
                QUERYING_NODE_LIST = [node for node in QUERYING_NODE_LIST if node['name'] != name_field ]
                # add the new QUERY records for the client
                my_query_node_record = QueryingNodeDict(name_field,time.time(),records)
                QUERYING_NODE_LIST.append(my_query_node_record)
                # OK now send the reply back
                send_query_records(records,client_socket,client_address,node_cert)
                
    client_socket.close()
    return

# Function to manage the list and remove records from the serving node list that are not fresh
def list_manager():
    global SERVING_NODE_LIST_LOCK
    global SERVING_NODE_LIST
    while True:
        with SERVING_NODE_LIST_LOCK:
            # removing entries that are not fresh
            current_time = time.time()
            SERVING_NODE_LIST = [node for node in SERVING_NODE_LIST if (current_time - node['timestamp'] <= AVAILABILITY_RECORD_EXPIRATION_SECONDS) ]
        time.sleep(AVAILABILITY_LIST_REFRESH_SECONDS)

def accept_query_client(query_server_socket):
    while True:
        # print(f"{YELLOW}accept_query_client waiting for connection from some node...{RESET}\n",flush=True)
        query_client_socket, query_client_address = query_server_socket.accept()
        # print(f"{GREEN}accept_query_client received connection from some node...{RESET}",flush=True)
        query_client_handle_thread = threading.Thread(target=handle_query_client, args=(query_client_socket, query_client_address))
        query_client_handle_thread.start()
    pass

def accept_availability_client(availability_server_socket):
    while True:
        # print(f"{YELLOW}accept_availability_client waiting for connection from some node...{RESET}\n",flush=True)
        availability_client_socket, availability_client_address = availability_server_socket.accept()
        # print(f"{GREEN}accept_availability_client received connection from some node...{RESET}",flush=True)
        availability_client_handle_thread = threading.Thread(target=handle_availability_client, args=(availability_client_socket, availability_client_address))
        availability_client_handle_thread.start()
    pass

def sync_P2P_ntp():
    # Tell the ntp_helpers module to sync with the NTP server for timestamp checking
    print("P2P: NTP sync in progress...")
    ntp_sync()
    print(f"{GREEN}NTP sync completed!{RESET}")

def P2Pstarter():
    try:
        sync_P2P_ntp()
        
        # TCP/IP SOCKETS INITIALIZATION

        # Starting socket for QUERYING SERVER (i.e. the server that a node quries to discover other peers)
        print("P2P: QUERY server initiating...")
        query_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        query_server_address = ( get_IPv4_with_internet_access() , QUERY_SERVER_PORT)
        query_server_socket.bind(query_server_address)
        query_server_socket.listen(MAX_QUERY_SERVER_CONNECTIONS)
        print(f"{GREEN}P2P: QUERY server ready & listening!{RESET}")

        # Starting socket for AVAILABILITY SERVER (i.e. the server that a node solicits its availability to)
        print("P2P: AVAILABILITY server initiating...",flush=True)
        availability_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        availability_server_address = ( get_IPv4_with_internet_access() , AVAILABILITY_SERVER_PORT)
        debug_availability_server_address = ( get_IPv4_with_internet_access() , AVAILABILITY_SERVER_PORT)
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
    except Exception as e:
        print(f"{RED}Could not start the P2P services correctly:\n{e}{RESET}")
        return False

    return True

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

    a = P2Pstarter()

if __name__ == "__main__":
    P2Pmain()

# client solicits to this server once he connects to it. This IP addresses along with 
# the ports will be saved in a list which I mention about below. The second thread will 
# be receiving in raw bytes from the client; that is an IP address and a port and this 
# will be saved in a list along with a timestamp that is the timestamp of the time that 
# they were written in the list. There will be a third thread that will be used for keeping 
#the contents of the list fresh; that is if an item on the list in more than 
# 2 minutes old it will be erased from the list.
