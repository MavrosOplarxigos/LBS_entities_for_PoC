# This file will manage the different entities and provide support information to the users.
import signal
import sys
import threading
import SharedVarsExperiment
from colorama import init, Fore
from P2P_relay_server import *
from ntp_helpers import *
from debug_colors import *
from signing_server import *
from tcp_helpers import *

# Configuration
SERVICE_PORT = 55444 # This port should be hardcoded in the Android site
MAX_SERVICE_CONNECTIONS = 10
SERVICE_SOCKET_TIMEOUT_S = 10

# Experiment configuration

# to configure
EXPERIMENT_START_EXPECTED_PARTICIPANTS = 5
EXPERIMENT_ANSWER_PROBABILITY_PCENT_MIN = 0
EXPERIMENT_ANSWER_PROBABILITY_PCENT_MAX = 100
EXPERIMENT_ANSWER_PROBABILITY_PCENT_INTERVAL = 10
SHOULD_PEER_REASK = 0
RECORDS_TO_ACQUIRE_MIN = 1
RECORDS_TO_ACQUIRE_MAX = 5
QUERIES_PER_EXPERIMENT = 100

# orchestation
EXPERIMENT_READY_PARTICIPANTS_LOCK = threading.Lock()
EXPERIMENT_PARTICIPANTS_COUNTER = 0
EXPERIMENT_PARTICIPANTS_SOCKETS = []
IS_EXPERIMENT = False
# other specifics (not implemented yet)
# PARTICIPANTS_MIN = 3
# PARTICIPANTS_MAX = 3 # Number of max devices that we want to have
# PARTICIPANT_INTERVAL = 1 # How many participants do we jump per experiment

import pandas as pd
import matplotlib.pyplot as plt
data_filename = "experiment_data.txt"

def analysis_generate_graph():
    # Initialize variables to store data
    line_data = {}  # Dictionary to store data for each line
    colors = plt.cm.viridis(range(0, 256, 256 // 10))  # Generate a set of distinct colors
    markers = ['o', 's', '^', 'D', 'v', 'p', '*', 'H', '<', '>']
    # Read data from the file
    with open(data_filename, "r") as file:
        for line in file:
            line_number, x, y = map(float, line.split())
            if line_number not in line_data:
                line_data[line_number] = {"x": [], "y": []}
            line_data[line_number]["x"].append(x)
            line_data[line_number]["y"].append(y)
    # Create a plot with different colors for each line
    for line_number, data in line_data.items():
        plt.plot(data["x"], data["y"], label=f'Peer records = {line_number}', color=colors[int(line_number) % len(colors)], marker=markers[ int(line_number) % len(markers) ] )
    # Add labels, legend, and title
    plt.ylim(0, 1)
    plt.xlim(0,100)
    plt.xlabel('Percent Probability of Service')
    plt.ylabel('Peer-Hit Ratio')
    plt.legend()
    plt.title('Data Points from File')
    # Save the plot to a picture file (e.g., PNG)
    plt.savefig('test_plot.png')
    # Display the plot (optional)
    plt.show()

def analysis_clear_data_file():
    with open(data_filename,"w") as file:
        pass
        return

def analysis_write_point(records_returned_line,answer_prob,TOTAL,MISSES):
    with open(data_filename,"a") as file:
        if TOTAL == 0:
            print(f"{RED}OK now it's verified that for some reason we get 0 total requests on the counter{RESET}",flush=True)
            exit()
        peer_hit_ratio = (float)(TOTAL-MISSES) / (float)(TOTAL)
        to_write = f"{records_returned_line} {answer_prob} {peer_hit_ratio}\n"
        file.write(to_write)
    return

def experiment_counters_reset():
    with SharedVarsExperiment.SS_COUNTERS_LOCK:
        SharedVarsExperiment.SS_REQUESTS_RECEIVED = 0
        SharedVarsExperiment.SS_REQUESTS_DIRECT = 0
        SharedVarsExperiment.PEER_HITS = 0
        SharedVarsExperiment.PEER_MISSES = 0

def start_experiment():

    SharedVarsExperiment.P2P_CHECK_IS_EXPERIMENT = True
    SharedVarsExperiment.NTP_CHECK_IS_EXPERIMENT = True
    global SERVICE_SOCKET_TIMEOUT_S = 60 # in-experiments we increase the tolerance

    analysis_clear_data_file()
    global SHOULD_PEER_REASK
    global RECORDS_TO_ACQUIRE_MIN
    global RECORDS_TO_ACQUIRE_MAX
    global QUERIES_PER_EXPERIMENT
    global EXPERIMENT_ANSWER_PROBABILITY_PCENT_MIN
    global EXPERIMENT_ANSWER_PROBABILITY_PCENT_MAX
    global EXPERIMENT_ANSWER_PROBABILITY_PCENT_INTERVAL
    global EXPERIMENT_PARTICIPANTS_SOCKETS
    global IS_EXPERIMENT

    print(f"{CYAN}Experiments will start in 5 seconds!{RESET}")
    for i in range(4):
        print(f"{CYAN}Experiments start in {5-i-1} seconds!{RESET}")
        time.sleep(1)
    print(f"{GREEN}Experiments running!{RESET}")

    # send the number of experiments
    number_of_experiments = (int)( ((RECORDS_TO_ACQUIRE_MAX-RECORDS_TO_ACQUIRE_MIN)+1) * ( ((EXPERIMENT_ANSWER_PROBABILITY_PCENT_MAX-EXPERIMENT_ANSWER_PROBABILITY_PCENT_MIN)/EXPERIMENT_ANSWER_PROBABILITY_PCENT_INTERVAL)+1) )

    print(f"{CYAN}RECORDS TO ACQUIRE MAX = {RECORDS_TO_ACQUIRE_MAX}{RESET}")
    print(f"{CYAN}RECORDS TO ACQUIRE MIN = {RECORDS_TO_ACQUIRE_MIN}{RESET}")

    print(f"{CYAN}We will run {number_of_experiments} experiments!{RESET}",flush=True)
    NUMBER_OF_EXPERIMENTS_BYTES = struct.pack('<I',(int)(number_of_experiments))
    send_to_all_client_sockets(EXPERIMENT_PARTICIPANTS_SOCKETS,NUMBER_OF_EXPERIMENTS_BYTES)

    experiment_counter = 0
    HAS_HAD_ZERO_PEERS = 0

    SECONDS_EXPERIMENT_BEGIN = time.time()
    for RECS_TO_GET in range(RECORDS_TO_ACQUIRE_MIN,RECORDS_TO_ACQUIRE_MAX+1):
        for ANS_PROB in range(EXPERIMENT_ANSWER_PROBABILITY_PCENT_MIN,EXPERIMENT_ANSWER_PROBABILITY_PCENT_MAX+1,EXPERIMENT_ANSWER_PROBABILITY_PCENT_INTERVAL):

            # Configure the variables and communicate configuration to the receiving client
            SharedVarsExperiment.RECORDS_TO_ACQUIRE_PER_QUERY = RECS_TO_GET
            SharedVarsExperiment.OVERRIDE_AVAILABILITY_CHECKS_ON_EARLY_REASKS = 1
            experiment_counter+=1
            EXPERIMENT_COUNTER_BYTES = struct.pack('<I',(int)(experiment_counter))
            send_to_all_client_sockets(EXPERIMENT_PARTICIPANTS_SOCKETS,EXPERIMENT_COUNTER_BYTES)
            ANS_PROB_BYTES = struct.pack('<I',(int)( ANS_PROB ) )
            send_to_all_client_sockets(EXPERIMENT_PARTICIPANTS_SOCKETS,ANS_PROB_BYTES)
            REASK_BYTES = b"YES" if (SHOULD_PEER_REASK>0) else b"NOP"
            send_to_all_client_sockets(EXPERIMENT_PARTICIPANTS_SOCKETS,REASK_BYTES)
            QUERIES_PER_EXPERIMENT_BYTES = struct.pack('<I',(int)( QUERIES_PER_EXPERIMENT) )
            send_to_all_client_sockets(EXPERIMENT_PARTICIPANTS_SOCKETS,QUERIES_PER_EXPERIMENT_BYTES)

            # reset the counters of the experiment
            experiment_counters_reset()

            time.sleep(2) # We are giving all the experiment threads on the devices time to read the data send before we send the signal to start this instance of the experiment

            print(f"{CYAN}\nNow on experiment #{experiment_counter}\n" +
                    f"Serving peer records received per query = {RECS_TO_GET}\n" +
                    f"Serving probability = {ANS_PROB}%\n"
                    +f"{RESET}",flush=True)

            # send the signal to start
            send_to_all_client_sockets(EXPERIMENT_PARTICIPANTS_SOCKETS,b"START")

            # the devices run the experiment independetly
            print(f"{CYAN}Experiment #{experiment_counter} is now running. The START signal was send to all the epxeriment participants{RESET}")

            # wait for all of the partiicipants to send back that they have finished
            for client_socket in EXPERIMENT_PARTICIPANTS_SOCKETS:
                
                peer_status_option = blocking_receive_all(client_socket,4)
                decoded_text_peer_status_option = peer_status_option.decode('utf-8')

                if decoded_text_peer_status_option == "FAIL":
                    HAS_HAD_ZERO_PEERS = 1
                    print(f"{RED}There is a peer which had 0 serving peer records at one point{RESET}")

                this_peer_hits_bytes = blocking_receive_all(client_socket,4)
                this_peer_hits = struct.unpack('>I',this_peer_hits_bytes)[0]
                SharedVarsExperiment.PEER_HITS += this_peer_hits
                SharedVarsExperiment.PEER_MISSES += QUERIES_PER_EXPERIMENT - this_peer_hits
                print(f"{GREEN}Client sent: {SharedVarsExperiment.PEER_HITS} hits and {SharedVarsExperiment.PEER_MISSES} misses.{RESET}")

            print(f"{CYAN}All devices have returned their DONE for experiment #{experiment_counter}{RESET}")
            print(f"{CYAN}TOTAL REQUESTS RECEIVED = {SharedVarsExperiment.SS_REQUESTS_RECEIVED}{RESET}")
            print(f"{CYAN}REQUESTS THAT WERE DIRECT = {SharedVarsExperiment.SS_REQUESTS_DIRECT}{RESET}")
            print(f"{CYAN}PEER HITS = {SharedVarsExperiment.PEER_HITS}{RESET}")
            print(f"{CYAN}PEER MISSES = {SharedVarsExperiment.PEER_MISSES}{RESET}")

            # sanity check that all requests are as we expect
            if ( QUERIES_PER_EXPERIMENT * len(EXPERIMENT_PARTICIPANTS_SOCKETS) ) != ( SharedVarsExperiment.PEER_HITS + SharedVarsExperiment.PEER_MISSES ):
                expected_was = ( QUERIES_PER_EXPERIMENT * len(EXPERIMENT_PARTICIPANTS_SOCKETS) )
                actual_was = ( SharedVarsExperiment.PEER_HITS + SharedVarsExperiment.PEER_MISSES )
                print(f"{RED}We have a problem with the last experiment because expected original queries were {expected_was} and actual were {actual_was}{RESET}")

            TOTAL_ORIGINAL_QUERIES = ( SharedVarsExperiment.PEER_HITS + SharedVarsExperiment.PEER_MISSES )
            analysis_write_point(RECS_TO_GET,ANS_PROB,TOTAL_ORIGINAL_QUERIES,SharedVarsExperiment.PEER_MISSES)

    SECONDS_EXPERIMENT_END = time.time()
    SECONDS_FOR_ALL_EXPERIMENTS = SECONDS_EXPERIMENT_END - SECONDS_EXPERIMENT_BEGIN
    print(f"{CYAN}The time taken for ALL experiments to run was {SECONDS_FOR_ALL_EXPERIMENTS} seconds.{RESET}")

    if HAS_HAD_ZERO_PEERS == 1:
        print(f"{RED}There was at least an experiment where a node has had 0 serving peer records at some point{RESET}")

    analysis_generate_graph()
    time.sleep(10)
    exit()
    return

# Reply to INFO Strucutre:
# [ONLINE] | [P2P_RELAY_QUERY_PORT] | [P2P_RELAY_AVAILABILITY_PORT] | [SIGNING_FWD_SERVER_PORT]
# [   6  ] | [         4          ] | [             4             ] | [          4            ]
def reply_INFO_byte_array():

    online_bytes = b"ONLINE"
    # print("online_bytes array = ",online_bytes)
    online_bytes_string = online_bytes.decode('utf-8')
    # print("online_bytes string = ",online_bytes_string)
    
    P2P_RELAY_QUERY_PORT = struct.pack('<I',QUERY_SERVER_PORT)
    # print("P2P_RELAY_QUERY_PORT byte array = ",P2P_RELAY_QUERY_PORT)
    P2P_RELAY_QUERY_PORT_INT = ( struct.unpack('<I',P2P_RELAY_QUERY_PORT) )[0]
    # print("P2P_RELAY_QUERY_PORT_INT = ",P2P_RELAY_QUERY_PORT_INT)

    P2P_RELAY_AVAILABILITY_PORT = struct.pack('<I',AVAILABILITY_SERVER_PORT)
    # print("P2P_RELAY_AVAILABILITY_PORT byte array = ",P2P_RELAY_AVAILABILITY_PORT)
    P2P_RELAY_AVAILABILITY_PORT_INT = (struct.unpack('<I',P2P_RELAY_AVAILABILITY_PORT))[0]
    # print("P2P_RELAY_AVAILABILITY_PORT_INT = ",P2P_RELAY_AVAILABILITY_PORT_INT)

    SIGNING_FWD_SERVER_PORT = struct.pack('I',FWD_SERVER_PORT)
    # print("SIGNING_FWD_SERVER_PORT byte array = ",SIGNING_FWD_SERVER_PORT)
    SIGNING_FWD_SERVER_PORT_INT = (struct.unpack('<I',SIGNING_FWD_SERVER_PORT))[0]
    # print("SIGNING_FWD_SERVER_PORT_INT = ",SIGNING_FWD_SERVER_PORT_INT)

    info_reply = (
            online_bytes +
            P2P_RELAY_QUERY_PORT +
            P2P_RELAY_AVAILABILITY_PORT +
            SIGNING_FWD_SERVER_PORT
            )

    # print(f"The INFO reply is {RED}{info_reply}{RESET}")
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


def reply_CRDS(client_socket,client_address):

    try:
        # CRDS expected structure:
        # [NODE_NAME_LENGTH] | [   NODE_NAME    ]
        # [       4        ] | [NODE_NAME_LENGTH]

        NODE_NAME_LENGTH_bytes = receive_all(client_socket,4)
        #print("Node length byte array: ",NODE_NAME_LENGTH_bytes)
        #NODE_NAME_LENGTH_little = struct.unpack('<i',NODE_NAME_LENGTH_bytes)[0]
        #print("LITTLE length as print ",NODE_NAME_LENGTH_little)
        NODE_NAME_LENGTH_big = struct.unpack('>i',NODE_NAME_LENGTH_bytes)[0]
        # print("NODE_NAME_LENGTH_big = ",NODE_NAME_LENGTH_big)

        NODE_NAME_bytes = receive_all(client_socket,NODE_NAME_LENGTH_big)
        NODE_NAME = NODE_NAME_bytes.decode('utf-8')
        # print(f"Node name form {client_address}: {NODE_NAME}")

        # Reply with VALID or INVLD whether the name exists in the CA or not
        if exists_name(NODE_NAME):
            send_all(client_socket,b"VALID")
            # print(f"{GREEN}The name {NODE_NAME} from {client_address} is valid!")
        else:
            send_all(client_socket,b"INVLD")
            print(f"{RED}The name {NODE_NAME} from {client_address} is not registered with the CA!{RESET}")
            return True

        # reply structure NODE PRIVATE KEY:
        # [ NODE PRIVATE KEY LENGTH ] | [     NODE PRIVATE KEY    ]
        # [         4               ] | [ NODE PRIVATE KEY LENGTH ]

        NODE_PRIVATE_KEY = read_private_from_file_as_byte_array(NODE_NAME)
        NODE_PRIVATE_KEY_LENGTH = struct.pack('<I',len(NODE_PRIVATE_KEY))
        private_key_data = (NODE_PRIVATE_KEY_LENGTH + NODE_PRIVATE_KEY)
        send_all(client_socket,private_key_data)
        # print( f"Private key sent to {client_address} aka " + NODE_NAME )

        # reply structure NODE CERTIFICATE:
        # [ NODE CERTIFICATE LENGTH ] | [     NODE CERTIFICATE    ]
        # [            4            ] | [ NODE CERTIFICATE LENGTH ]
        NODE_CERTIFICATE = read_certificate_from_file_as_byte_array(NODE_NAME)
        NODE_CERTIFICATE_LENGTH = struct.pack('<I',len(NODE_CERTIFICATE))
        certificate_data = (NODE_CERTIFICATE_LENGTH + NODE_CERTIFICATE)
        send_all(client_socket,certificate_data)
        # print( f"Node certificate sent to {client_address} aka " + NODE_NAME )

        # reply structure CA CERTIFICATE:
        # [ CA CERTIFICATE LENGTH ] | [     CA CERTIFICATE    ]
        # [          4            ] | [ CA CERTIFICATE LENGTH ]
        CA_CERTIFICATE_for_node = read_CA_certificate_from_file_as_byte_array()
        CA_CERTIFICATE_LENGTH_for_node = struct.pack('<I',len(CA_CERTIFICATE_for_node))
        CA_certificate_data = (CA_CERTIFICATE_LENGTH_for_node + CA_CERTIFICATE_for_node)
        send_all(client_socket,CA_certificate_data)
        # print( f"CA certificate sent to {client_address} aka " + NODE_NAME )

        # reply strucutre psuedonymous certificates/private keys
        # we have 4 psuedonymous certificates/private key pairs
        for i in range(1,5):
            # [ NODE PCERT LENGTH ] | [ NODE PCERT   ] | [ NODE PPKEY LENGTH ] | [   NODE PPKEY  ]
            # [        4          ] | [NODE PCERT LEN] | [         4         ] | [ NODE PPKEY LEN]

            # retrieving the data
            PCERT_PATH = path_to_node_Pcert_by_name(NODE_NAME,i)
            PPKEY_PATH = path_to_node_Pprivate_by_name(NODE_NAME,i)
            NODE_PCERT = file_as_byte_array(PCERT_PATH)
            NODE_PPKEY = file_as_byte_array(PPKEY_PATH)
            NODE_PCERT_LEN = len(NODE_PCERT)
            packed_NODE_PCERT_LEN = struct.pack('<I',NODE_PCERT_LEN)
            NODE_PPKEY_LEN = len(NODE_PPKEY)
            packed_NODE_PPKEY_LEN = struct.pack('<I',NODE_PPKEY_LEN)

            # print(f"Pseudo-credentials #{i} for {NODE_NAME} have been sent.")

            # sending the data (if this proves slow we might need to change the socket timeout)
            pseudo_data = ( packed_NODE_PCERT_LEN + NODE_PCERT + packed_NODE_PPKEY_LEN + NODE_PPKEY
                    )
            send_all(client_socket,pseudo_data)
    
        return True
    except Exception as e:
        print("Error trying to send CRDS reply:",e)
        return False

def handle_client(client_socket,client_address):
    try:
        # print(f"{YELLOW}Waiting for client @ {client_address} to send a message!{RESET}",flush=True)
        client_socket.settimeout(SERVICE_SOCKET_TIMEOUT_S)
        option = receive_all(client_socket,4)
        option = option.decode('utf-8')
        print(f"{YELLOW}{option} REQUEST from @ {client_address}!{RESET}",flush=True)
        # INFO: sent by the client to check that the service is online and to get information
        # about the ports of the P2P relay server and the signing server
        if option == "INFO":
            # print(f"Client {client_address} requested INFO")
            status_reply_INFO = reply_INFO(client_socket)
            if status_reply_INFO:
                print(f"{GREEN}INFO REPLY sent to {client_address} sent SUCESSFULLY!{RESET}")
            else:
                print(f"{RED}INFO REPLY to {client_address} fail!{RESET}")
        # CRDS: sent by the client when credentials are needed to be able to communicate with
        # the LBS entities.
        elif option == "CRDS":
            # print(f"Client {client_address} requested credentials.")
            status_reply_CRDS = reply_CRDS(client_socket,client_address)
            if status_reply_CRDS:
                print(f"{GREEN}CRDS REPLY sent to {client_address} SUCCESSFULLY!{RESET}")
            else:
                print(f"{RED}CRDS request REPLY to {client_address} fail!{RESET}")
        elif option == "EXPR":
            client_socket.settimeout(0) # We expect this to cause the socket to never drop the connection
            # a client declares readiness to join an experiment
            global IS_EXPERIMENT
            if not IS_EXPERIMENT:
                print(f"{CYAN}Closing experiment socket with {client_address}{RESET}")
                client_socket.close()
                return
            global EXPERIMENT_READY_PARTICIPANTS_LOCK
            with EXPERIMENT_READY_PARTICIPANTS_LOCK:
                global EXPERIMENT_PARTICIPANTS_COUNTER
                EXPERIMENT_PARTICIPANTS_COUNTER += 1
                global EXPERIMENT_PARTICIPANTS_SOCKETS
                EXPERIMENT_PARTICIPANTS_SOCKETS.append(client_socket)
                if EXPERIMENT_PARTICIPANTS_COUNTER == EXPERIMENT_START_EXPECTED_PARTICIPANTS:
                    experiment_thread = threading.Thread(target=start_experiment)
                    experiment_thread.daemon = True
                    experiment_thread.start()
                # since we don't want to close this socket we will return
                return
        client_socket.close()
        return
    except Exception as e:
        print(f"{RED}Error with connection from client to the service orchestrator{RESET}",flush=True)
        return

def accept_client(server_socket):
    try:
        while True:
            client_socket, client_address = server_socket.accept()
            # print(f"{YELLOW}Accepted client connection from {client_address}{RESET}",flush=True)
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
    # Color setting for debugs
    init(autoreset=True)
    # Tell the ntp_helpers module to sync with the NTP server for timestamp checking
    print("NTP sync in progress...")
    ntp_sync()
    print(f"{GREEN}NTP sync completed!{RESET}")
    # Read CA credentials
    print("Retrieving CA credentials...")
    read_CA_private_from_file()
    read_CA_certificate_from_file()
    print(f"{GREEN}CA credentials retrieved!{RESET}")

def main():

    inits()
    
    # check if it is experiment
    global IS_EXPERIMENT
    IS_EXPERIMENT = (True if '-E' in sys.argv else False)

    if IS_EXPERIMENT:
        SharedVarsExperiment.RECORDS_TO_ACQUIRE_PER_QUERY = RECORDS_TO_ACQUIRE_MIN
        print(f"{CYAN}It {GREEN}is{CYAN} experiment mode!{RESET}")
    else:
        print(f"{CYAN}It {GREEN}is not{CYAN} experiment mode!{RESET}")

    try:

        # Start P2P related services
        p2p_ready = P2Pstarter()
        if not p2p_ready:
            print(f"{RED}Error: Could not start P2P services correctly!{RESET}")
            exit()

        ss_ready = SigningServerStarter()
        if not ss_ready:
            print(f"{RED}Error: Could not start the SS services correctly!{RESET}")
            exit()

        signal.signal(signal.SIGINT, signal_handler)        
        # The main service for providing clients with necessary information to allow for the
        # scheme to work will start last after all other services. So that when we reply to the
        # user that we are online that means that all services/entities of the LBS scheme are online.
        print("Opening service socket...")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ( get_IPv4_with_internet_access() , SERVICE_PORT)
        server_socket.bind(server_address)
        ip_address_server = socket.gethostbyname(server_address[0])
        print(f"{YELLOW}IP Address: {ip_address_server}:{server_address[1]}{RESET}")
        server_socket.listen(MAX_SERVICE_CONNECTIONS)
        print(f"{GREEN}Service socket ready & listening!{RESET}")

        print("Initiating service connection accepting thread...")
        server_thread = threading.Thread(target=accept_client, args=(server_socket,))
        server_thread.daemon = True
        server_thread.start()
        print(f"{GREEN}Service connection accepting thread initiated!{RESET}",flush=True)
        time.sleep(2)
        clear_screen_and_reset_pointer()
        print(f"{GREEN}All system functionalities ready!{RESET}")

        # joining all threads so that the main thread doesn't terminate and controls
        # signal events to gracefully finish the program rather than throwing an exception
        # for the threads.
        server_thread.join()

    except Exception as e:
        print("Main program flow error: ",e)

if __name__ == "__main__":
    main()
