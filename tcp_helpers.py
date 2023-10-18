import socket
import psutil
import time
from debug_colors import *

def byte_array_first_10_bytes_decimal(x):
    ans = []
    for i in range(0,min(10,len(x))):
        byte_decimal = int(x[i])
        ans.append( (str(byte_decimal)) )
    return ans

def all_interfaces_names():
    for interface, addrs in psutil.net_if_addrs().items():
        print(f"{GREEN}Interface Name: {interface}{RESET}")
        for addr in addrs:
            print(f"-> Address: {addr.address} Family: {addr.family}")
        print()

def name_to_CN_only(x):
    return str(x[3:8])

def IP_TO_INT(x):
    return int.from_bytes(socket.inet_aton(x), byteorder='big')

INTERNET_CONNECTED_IPv4 = None

def try_address_internet(my_address,debug_name):
    global INTERNET_CONNECTED_IPv4
    sites = [ "google.com", "facebook.com", "example.com", "something.com" ]
    for site in sites:
        try:
            socket_address = (my_address,0)
            site_address = (site,80)
            client_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            client_socket.bind(socket_address)
            client_socket.settimeout(5000)
            client_socket.connect(site_address)
            time.sleep(2)
            client_socket.close()
            INTERNET_CONNECTED_IPv4 = my_address
            print(f"{GREEN}Used the {debug_name} to connect to the Internet{RESET}")
            return True
        except Exception as e:
            print(f"{ORANGE}Could not connect to {site_address} because of " + str(e) + f"{RESET}")
            continue
    print(f"{RED}Could not use the {debug_name} to connect to the Internet{RESET}")
    return False

def get_IPv4_with_internet_access():

    global INTERNET_CONNECTED_IPv4
    if INTERNET_CONNECTED_IPv4 != None:
        return INTERNET_CONNECTED_IPv4

    ethernet_address = IPv4_ethernet_address()
    wifi_address = IPv4_wifi_address()

    if try_address_internet(wifi_address,"WiFi"):
        return INTERNET_CONNECTED_IPv4

    if try_address_internet(ethernet_address,"Ethernet"):
        return INTERNET_CONNECTED_IPv4
    
    print(f"{RED}Could not connect to the internet with EITHER interface!{RESET}")
    
    return None

def IPv4_wifi_address():
    for interface, addrs in psutil.net_if_addrs().items():
        if "Wi-Fi" in interface:
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    return addr.address
    return None

def IPv4_ethernet_address():
    for interface, addrs in psutil.net_if_addrs().items():
        if interface == "Ethernet":
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    return addr.address
    return None

def receive_all(sock, size):
    # print("Entered receive_all")
    data = b''
    while len(data) < size:
        # print("Waiting for ",str((size - len(data)))) 
        chunk = sock.recv(size - len(data))
        # print("Received the chunk")
        if not chunk:
            raise EOFError("Receiving: Socket connection broken.")
        data += chunk
    return data

def blocking_receive_all(sock,size):
    original_timeout = sock.gettimeout()
    sock.settimeout(None)
    data = b''
    try:
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                raise EOFError("Receiving: Socket connection broken.")
            data += chunk
    finally:
        sock.settimeout(original_data)
    return data

def send_all(sock,data):
    total_bytes_sent = 0
    while total_bytes_sent < len(data):
        sent = sock.send(data[total_bytes_sent:])
        if sent == 0:
            raise RuntimeError("Sending: Socket connection broken.")
        total_bytes_sent += sent

def send_to_all_client_sockets(sockets,data):
    for client_socket in sockets:
        send_all(client_socket,data)

def close_connection(client_socket, client_address):
    print(f"Connection with {client_address} closed.")
    client_socket.close()

def main():
    init(autoreset=True)
    all_interfaces_names()
    the_address = physical_ethernet_address()
    print(f"The address we care about: {YELLOW}{the_address}{RESET}")

if __name__ == "__main__":
    main()
