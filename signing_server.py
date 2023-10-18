from tcp_helpers import *
from ntp_helpers import *
from CA_server import *
from debug_colors import *
from caching import *

import socket
import threading
import traceback
import struct
import time
import requests
import json
import SharedVarsExperiment

FWD_SERVER_PORT = 50003
MAX_SS_CONNECTIONS = 40 # How many signing requests will we be trying to answer simultaneously
SS_CERTIFICATE = retrieve_CA_certificate()
SS_PRIVATE = retrieved_CA_private()
TRIED_LOADING_CACHE = 0

def fullfil_URL_request(requestURL):
    
    global TRIED_LOADING_CACHE
    if not TRIED_LOADING_CACHE:
        loaded = caching.data_loading()
        if not loaded:
            print(f"{RED}Error: Could not load cache!{RESET}")
        else:
            print(f"{GREEN}Cache loaded successfully!{RESET}")
        TRIED_LOADING_CACHE = 1

    cached_record = caching.data_record_retrieve(requestURL)
    if cached_record != None:
        print(f"{GREEN}Cache HIT: {requestURL}{RESET}")
        return cached_record

    try:
        response = requests.get(requestURL)
        if response.status_code == 200:

            # checking that we got a valid JSON format
            # if not an exception json.JSONDecodeError will be thrown
            json_data = json.loads(response.content)

            try:
                print(f"{RED}Cache MISS: {requestURL}{RESET}")
                caching.data_write(requestURL,response.content)
                caching.data_saving()
            except Exception as e:
                print(f"{RED}Error: Could not save the Cache file!{RESET}")

            return response.content
        else:
            print(f"{RED}SS: Could not fulfil the request: {requestURL} status code {response.status_code}{RESET}")
            return None

    except Exception as e:
        
        print(f"URL request error: {e}")
        return None

def printSS(x):
    print("SS: " + x + "\n",flush=True)

# ["PROXY"] | [4_CERTIFICATE_LENGTH] | [SERVING PEER CERTIFICATE] | [4_API_CALL_ENC_LEN] | [API_CALL_ENC_SSKEY] | [8_TIMESTAMP] | [SIGNATURE_TQ_LEN] | [SIGNATURE_TIMESTAMP_QUERY]
def proxy_handle(client_socket, client_address):
    try:
        cert_length_bytes = receive_all(client_socket,4)
        CERTIFICATE_LENGTH = struct.unpack('>I',cert_length_bytes)[0]

        serving_peer_cert_bytes = receive_all(client_socket,CERTIFICATE_LENGTH)
        SERVING_PEER_CERTIFICATE = PEMcertificate_from_DER_byte_array(serving_peer_cert_bytes)
        subject_name = SERVING_PEER_CERTIFICATE.subject.rfc4514_string()
        
        # print(f"PROXY request certificate of serving node has name {subject_name}")

        is_CA_signed = certificate_issuer_check(SERVING_PEER_CERTIFICATE, SS_CERTIFICATE)
        if not is_CA_signed:
            print(f"{RED}Provided certificate from {client_address} for PROXY request is not signed by the CA.{RESET}")
            return

        api_call_enc_length_bytes = receive_all(client_socket,4)
        API_CALL_ENC_LENGTH = struct.unpack('>I',api_call_enc_length_bytes)[0]
        api_call_enc_sskey_bytes = receive_all(client_socket,API_CALL_ENC_LENGTH)
        API_CALL = decrypt_byte_array_with_private(api_call_enc_sskey_bytes,SS_PRIVATE)
        STRING_API_CALL = API_CALL.decode('utf-8')
        print(f"{MAGENTA}SS: PROXY request from {subject_name} carries URL: {STRING_API_CALL}{RESET}")

        timestamp_data = receive_all(client_socket,8)
        Timestamp = struct.unpack('>Q', timestamp_data)[0]
        # print(f"PROXY timestamp = {Timestamp}")
        
        # verify the timestamp is fresh
        is_timestamp_fresh = verify_timestamp_freshness(Timestamp)
        if not is_timestamp_fresh:
            print(f"{RED}SS: Proxy request with expired timestamp received from {subject_name}{RESET}")
            return

        # timestamp fresh then we move on to read the concatenated signature of the timestamp with the query

        signature_tq_len_bytes = receive_all(client_socket,4)
        SIGNATURE_TQ_LEN = struct.unpack('>I',signature_tq_len_bytes)[0]

        signature_timestamp_query_bytes = receive_all(client_socket,SIGNATURE_TQ_LEN)
        SIGNATURE_TIMESTAMP_QUERY = signature_timestamp_query_bytes # might have to revert the endianess for this one to work

        # now we verify the signature based on the serving peer certificate
        # (the serving peer has generated this signature using its private key)
        
        # might have to revert the endianess for timestamp_data
        concatenation = timestamp_data + API_CALL
        is_signature_valid = verify_signature(SIGNATURE_TIMESTAMP_QUERY,concatenation,SERVING_PEER_CERTIFICATE)

        if not is_signature_valid:
            print(f"{RED}SS: The signature on the concatenated TIMESTAMP+QUERY on the PROXY request from {subject_name} @ {client_address} for {STRING_API_CALL}{RESET}")
            return

        # the signature is valid thus we will fullfill the request
        ANSWER_BYTE_ARRAY = fullfil_URL_request(STRING_API_CALL)

        if ANSWER_BYTE_ARRAY == None:
            print(f"{RED}SS: Error: Could NOT fulfil PROXY request {STRING_API_CALL} for {subject_name}{RESET}")
            return

        f10Answer = byte_array_first_10_bytes_decimal(ANSWER_BYTE_ARRAY)
        raw_answer_len = len(ANSWER_BYTE_ARRAY)
        
        # we have the answer and we have to communicate it back to the serving peer
        # SIGNING SERVER ANSWER FORWARD phase
        # [ENC_ANSWER_LENGTH] | [ENC_ANSWER] | [SIGNATURE_SS_QA_LEN] | [SIGNATURE_SS_QA] | [DEC_ANSWER_LEN]
        DEC_ANSWER_LEN = struct.pack('<I',len(ANSWER_BYTE_ARRAY))
        ENC_ANSWER = encrypt_byte_array_with_public(ANSWER_BYTE_ARRAY,SERVING_PEER_CERTIFICATE)
        ENC_ANSWER_LENGTH = struct.pack('<I',len(ENC_ANSWER))
        concatenateQA = API_CALL + ANSWER_BYTE_ARRAY
        SIGNATURE_SS_QA = sign_byte_array_with_private(concatenateQA,SS_PRIVATE)
        SIGNATURE_SS_QA_LEN = struct.pack('<I',len(SIGNATURE_SS_QA))

        SS_ANSWER_FWD = (
                ENC_ANSWER_LENGTH+
                ENC_ANSWER+
                SIGNATURE_SS_QA_LEN+
                SIGNATURE_SS_QA+
                DEC_ANSWER_LEN
                )

        ss_answer_fwd_len = len(SS_ANSWER_FWD)
        SS_ANSWER_LEN_BYTES = struct.pack('<I',ss_answer_fwd_len)
        send_all(client_socket,SS_ANSWER_LEN_BYTES) # 4 bytes to let the user know how long the answer will be

        print(f"{MAGENTA}SS: The reply message to the {RESET}{STRING_API_CALL}{MAGENTA} from {subject_name} is {GREEN}{ss_answer_fwd_len}{MAGENTA} bytes long and the first 10 bytes of the RAW ANSWER are {GREEN}{f10Answer} {MAGENTA}and its size is {GREEN}{raw_answer_len}  {RESET}")

        send_all(client_socket,SS_ANSWER_FWD)
        print(f"{GREEN}Sent answer to the PROXY request from {subject_name}{RESET}")
        return
    except Exception as e:
        print(f"{RED}Error when carrying out PROXY request from {client_address}{RESET}",e)
        traceback.print_exc()
        return

def direct_handle(client_socket, client_address):
    try:
        cert_length_bytes = receive_all(client_socket,4)
        CERTIFICATE_LENGTH = struct.unpack('>I',cert_length_bytes)[0]

        querying_peer_cert_bytes = receive_all(client_socket,CERTIFICATE_LENGTH)
        QUERYING_PEER_CERTIFICATE = PEMcertificate_from_DER_byte_array(querying_peer_cert_bytes)
        subject_name = QUERYING_PEER_CERTIFICATE.subject.rfc4514_string()

        is_CA_signed = certificate_issuer_check(QUERYING_PEER_CERTIFICATE, SS_CERTIFICATE)
        if not is_CA_signed:
            print(f"{RED}Provided certificate from {client_address} for DIRECT request is not signed by the CA.{RESET}")
            return

        api_call_enc_length_bytes = receive_all(client_socket,4)
        API_CALL_ENC_LENGTH = struct.unpack('>I',api_call_enc_length_bytes)[0]
        api_call_enc_sskey_bytes = receive_all(client_socket,API_CALL_ENC_LENGTH)
        API_CALL = decrypt_byte_array_with_private(api_call_enc_sskey_bytes,SS_PRIVATE)
        STRING_API_CALL = API_CALL.decode('utf-8')
        print(f"{MAGENTA}SS: DIRECT request from {subject_name} carries URL: {STRING_API_CALL}{RESET}")

        timestamp_data = receive_all(client_socket,8)
        Timestamp = struct.unpack('>Q', timestamp_data)[0]
        
        # verify the timestamp is fresh
        is_timestamp_fresh = verify_timestamp_freshness(Timestamp)
        if not is_timestamp_fresh:
            print(f"{RED}SS: Direct request with expired timestamp received from {subject_name}{RESET}")
            return

        signature_tq_len_bytes = receive_all(client_socket,4)
        SIGNATURE_TQ_LEN = struct.unpack('>I',signature_tq_len_bytes)[0]

        signature_timestamp_query_bytes = receive_all(client_socket,SIGNATURE_TQ_LEN)
        SIGNATURE_TIMESTAMP_QUERY = signature_timestamp_query_bytes # might have to revert the endianess for this one to work

        # now we verify the signature based on the qurying peer certificate
        # (the querying peer has generated this signature using its private key)
        
        # might have to revert the endianess for timestamp_data
        concatenation = timestamp_data + API_CALL
        is_signature_valid = verify_signature(SIGNATURE_TIMESTAMP_QUERY,concatenation,QUERYING_PEER_CERTIFICATE)

        if not is_signature_valid:
            print(f"{RED}SS: The signature on the concatenated TIMESTAMP+QUERY on the DIRECT request from {subject_name} @ {client_address} for {STRING_API_CALL}{RESET}")
            return

        # the signature is valid thus we will fullfill the request
        ANSWER_BYTE_ARRAY = fullfil_URL_request(STRING_API_CALL)

        if ANSWER_BYTE_ARRAY == None:
            print(f"{RED}SS: Error: Could NOT fulfil DIRECT request {STRING_API_CALL} for {subject_name}{RESET}")
            return

        f10Answer = byte_array_first_10_bytes_decimal(ANSWER_BYTE_ARRAY)
        raw_answer_len = len(ANSWER_BYTE_ARRAY)
        
        # we have the answer and we have to communicate it back to the serving peer
        # SIGNING SERVER ANSWER FORWARD phase
        # [ENC_ANSWER_LENGTH] | [ENC_ANSWER] | [SIGNATURE_SS_QA_LEN] | [SIGNATURE_SS_QA] | [DEC_ANSWER_LEN]
        DEC_ANSWER_LEN = struct.pack('<I',len(ANSWER_BYTE_ARRAY))
        ENC_ANSWER = encrypt_byte_array_with_public(ANSWER_BYTE_ARRAY,QUERYING_PEER_CERTIFICATE)
        ENC_ANSWER_LENGTH = struct.pack('<I',len(ENC_ANSWER))
        concatenateQA = API_CALL + ANSWER_BYTE_ARRAY
        SIGNATURE_SS_QA = sign_byte_array_with_private(concatenateQA,SS_PRIVATE)
        SIGNATURE_SS_QA_LEN = struct.pack('<I',len(SIGNATURE_SS_QA))

        SS_ANSWER_FWD = (
                ENC_ANSWER_LENGTH+
                ENC_ANSWER+
                SIGNATURE_SS_QA_LEN+
                SIGNATURE_SS_QA+
                DEC_ANSWER_LEN
                )

        ss_answer_fwd_len = len(SS_ANSWER_FWD)
        SS_ANSWER_LEN_BYTES = struct.pack('<I',ss_answer_fwd_len)
        send_all(client_socket,SS_ANSWER_LEN_BYTES) # 4 bytes to let the user know how long the answer will be

        print(f"{MAGENTA}SS: The reply message to the {RESET}{STRING_API_CALL}{MAGENTA} from {subject_name} is {GREEN}{ss_answer_fwd_len}{MAGENTA} bytes long and the first 10 bytes of the RAW ANSWER are {GREEN}{f10Answer} {MAGENTA}and its size is {GREEN}{raw_answer_len}  {RESET}")

        send_all(client_socket,SS_ANSWER_FWD)
        print(f"{GREEN}Sent answer to the DIRECT request from {subject_name}{RESET}")
        return
    except Exception as e:
        print(f"{RED}Error when carrying out DIRECT request from {client_address}{RESET}",e)
        traceback.print_exc()
        return
    return

def handle_ss_client(client_socket, client_address):

    print(f"{MAGENTA}SS: request from {client_address}{RESET}")

    # checking the option
    option = receive_all(client_socket,5)

    SharedVarsExperiment.SS_REQUESTS_RECEIVED += 1

    # PROXY: a serving node is requesting the fields for replying to a querying node
    if option == b"PROXY":
        proxy_handle(client_socket,client_address)
        return

    # DIREC: a querying node couldn't find any peers and it has to directly query the ss
    if option == b"DIREC":
        SharedVarsExperiment.SS_REQUESTS_DIRECT += 1
        direct_handle(client_socket,client_address)
        return

    print(f"{RED}SS: request from {client_address} has unknown option: {option}.{RESET}")
    return

def accept_ss_client(server_socket):
    while True:
        # print(f"{YELLOW}accept_ss_client waiting for connection from some node...{RESET}\n",flush=True)
        client_socket, client_address = server_socket.accept()
        # print(f"{GREEN}accepting_ss_client received connection from some node...{RESET}\n",flush=True)
        ss_client_handle_thread = threading.Thread(target=handle_ss_client, args=(client_socket,client_address))
        ss_client_handle_thread.start()
    pass

def sync_SS_ntp():
    # Tell the ntp_helpers module to sync with the NTP server for timestamp checking
    print(f"SS: NTP sync in progress...")
    ntp_sync()
    print(f"{GREEN}SS: NTP sync completed!{RESET}")

def SigningServerStarter():
    try:
        sync_SS_ntp()
        # TCP/IP SOCKETS INITIALIZATION
        print(f"SS: server initiating...")
        ss_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ss_address = (get_IPv4_with_internet_access(), FWD_SERVER_PORT)
        ss_socket.bind(ss_address)
        ss_socket.listen(MAX_SS_CONNECTIONS)
        print(f"{GREEN}SS: server listening!{RESET}")
        # THREAD INITIALIZATION
        print(f"SS: server connection thread initiating...")
        ss_thread = threading.Thread(target=accept_ss_client, args=(ss_socket,))
        ss_thread.daemon = True
        ss_thread.start()
        print(f"{GREEN}SS: server connection accepting thread started!{RESET}")
        return True
    except Exception as e:
        print(f"{RED}SS: Could not start services: {e}{RESET}")
        return False

def main():
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('', 56001)
    server_socket.bind(server_address)

    # Listen for incoming connections (up to 5 simultaneous connections)
    server_socket.listen(5)
    print("Server is listening on port 56001.")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(target=protocol, args=(client_socket, client_address))
            client_thread.start()
    except KeyboardInterrupt:
        print("Server shutting down.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()
