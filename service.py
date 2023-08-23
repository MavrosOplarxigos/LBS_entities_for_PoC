# This file will manage the different entities and provide support information to the users.
import signal
import sys
from colorama import init, Fore
from P2P_relay_server import *
from ntp_helpers import *
from debug_colors import *
from signing_server import *
from tcp_helpers import *

# Configuration
SERVICE_PORT = 55444 # This port should be hardcoded in the Android site
MAX_SERVICE_CONNECTIONS = 10
SERVICE_SOCKET_TIMEOUT_S = 5

# Reply to INFO Strucutre:
# [ONLINE] | [P2P_RELAY_QUERY_PORT] | [P2P_RELAY_AVAILABILITY_PORT] | [SIGNING_FWD_SERVER_PORT]
# [   6  ] | [         4          ] | [             4             ] | [          4            ]
def reply_INFO_byte_array():

    online_bytes = b"ONLINE"
    print("online_bytes array = ",online_bytes)
    online_bytes_string = online_bytes.decode('utf-8')
    print("online_bytes string = ",online_bytes_string)
    
    P2P_RELAY_QUERY_PORT = struct.pack('<I',QUERY_SERVER_PORT)
    print("P2P_RELAY_QUERY_PORT byte array = ",P2P_RELAY_QUERY_PORT)
    P2P_RELAY_QUERY_PORT_INT = ( struct.unpack('<I',P2P_RELAY_QUERY_PORT) )[0]
    print("P2P_RELAY_QUERY_PORT_INT = ",P2P_RELAY_QUERY_PORT_INT)

    P2P_RELAY_AVAILABILITY_PORT = struct.pack('<I',AVAILABILITY_SERVER_PORT)
    print("P2P_RELAY_AVAILABILITY_PORT byte array = ",P2P_RELAY_AVAILABILITY_PORT)
    P2P_RELAY_AVAILABILITY_PORT_INT = (struct.unpack('<I',P2P_RELAY_AVAILABILITY_PORT))[0]
    print("P2P_RELAY_AVAILABILITY_PORT_INT = ",P2P_RELAY_AVAILABILITY_PORT_INT)

    SIGNING_FWD_SERVER_PORT = struct.pack('I',FWD_SERVER_PORT)
    print("SIGNING_FWD_SERVER_PORT byte array = ",SIGNING_FWD_SERVER_PORT)
    SIGNING_FWD_SERVER_PORT_INT = (struct.unpack('<I',SIGNING_FWD_SERVER_PORT))[0]
    print("SIGNING_FWD_SERVER_PORT_INT = ",SIGNING_FWD_SERVER_PORT_INT)

    info_reply = (
            online_bytes +
            P2P_RELAY_QUERY_PORT +
            P2P_RELAY_AVAILABILITY_PORT +
            SIGNING_FWD_SERVER_PORT
            )

    print(f"The INFO reply is {RED}{info_reply}{RESET}")
    return info_reply

def testing_unpack_INFO(info_reply):
    print("---------------------- TESTING UNPACK -----------------")
    print(f"The size of the array is {len(info_reply)}")

    unpacked = struct.unpack('<6sIII', info_reply)
    online_status = unpacked[0].decode('utf-8')
    query_server_port = unpacked[1]
    availability_server_port = unpacked[2]
    signing_fwd_server_port = unpacked[3]
    print(f"Online Status: {online_status}")
    print(f"Query Server Port: {query_server_port}")
    print(f"Availability Server Port: {availability_server_port}")
    print(f"Signing FWD Server Port: {signing_fwd_server_port}")

def reply_INFO(client_socket):
    try:
        info_reply = reply_INFO_byte_array()
        send_all(client_socket,info_reply)
        return True
    except Exception as e:
        print("Error trying to send INFO reply:",e)
        traceback.print_exc()
        return False

def reply_CRDS(client_socket):

    return False

def handle_client(client_socket,client_address):
    print(f"{YELLOW}Waiting for client @ {client_address} to send a message!{RESET}",flush=True)
    client_socket.settimeout(SERVICE_SOCKET_TIMEOUT_S)
    option = receive_all(client_socket,4)
    option = option.decode('utf-8')
    print(f"{GREEN}Received option {option} from @ {client_address}!{RESET}")
    # INFO: sent by the client to check that the service is online and to get information
    # about the ports of the P2P relay server and the signing server
    if option == "INFO":
        print(f"Client {client_address} requested INFO")
        status_reply_INFO = reply_INFO(client_socket)
        if status_reply_INFO:
            print(f"{GREEN}Reply to INFO request from {client_address} sent!{RESET}")
        else:
            print(f"{RED}Reply to INFO request from {client_address} fail!{RESET}")
    # CRDS: sent by the client when credentials are needed to be able to communicate with
    # the LBS entities.
    elif option == "CRDS":
        print(f"Client {client_address} requested credentials.")
        status_reply_CRDS = reply_CRDS(client_socket)
        if status_reply_CRDS:
            print(f"{GREEN}Reply to CRDS request from {client_address} sent!{RESET}")
        else:
            print(f"{RED}Reply to CRDS request from {client_address} fail!{RESET}")
    # EXTR: option for extra infromation that the client might need to request for future.
    elif option == "EXTR":
        print(f"Client {client_address} requested extra information.")
    client_socket.close()
    return

def accept_client(server_socket):
    try:
        while True:
            client_socket, client_address = server_socket.accept()
            print(f"{YELLOW}Accepted client connection from {client_address}{RESET}",flush=True)
            client_handle_thread = threading.Thread(target=handle_client, args=(client_socket, client_address,))
            client_handle_thread.start()
    except Exception as e:
        print(f"{RED}Error in service connection accepting thread: ",e,"{RESET}")
        return

def signal_handler(signal, frame):
    print(f"{RED}Keyboard interrupt{RESET}")
    sys.exit(0)

def debug_INFO_message():
    INFO_ARRAY = reply_INFO_byte_array()
    print(f"The INFO_ARRAY is {INFO_ARRAY} and the length is {len(INFO_ARRAY)}")
    testing_unpack_INFO(INFO_ARRAY)
    return

def inits():
    init(autoreset=True)

def main():
    inits()
    try:
        signal.signal(signal.SIGINT, signal_handler)
        ntp_sync()
        
        # The main service for providing clients with necessary information to allow for the
        # scheme to work will start last after all other services. So that when we reply to the
        # user that we are online that means that all services/entities of the LBS scheme are online.
        print("Opening service socket...")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (physical_ethernet_address(), SERVICE_PORT)
        server_socket.bind(server_address)
        ip_address_server = socket.gethostbyname(server_address[0])
        print(f"{YELLOW}IP Address: {ip_address_server}:{server_address[1]}{RESET}")
        server_socket.listen(MAX_SERVICE_CONNECTIONS)
        print(f"{GREEN}Service socket ready & listening!{RESET}")

        print("Initiating service connection accepting thread...")
        server_thread = threading.Thread(target=accept_client, args=(server_socket,))
        server_thread.daemon = True
        server_thread.start()
        print(f"{GREEN}Service connection accepting thread initiated!{RESET}")

        # joining all threads so that the main thread doesn't terminate and controls
        # signal events to gracefully finish the program rather than throwing an exception
        # for the threads.
        server_thread.join()

    except Exception as e:
        print("Main program flow error: ",e)

if __name__ == "__main__":
    main()
