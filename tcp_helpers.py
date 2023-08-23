import socket
import psutil
from debug_colors import *

def all_interfaces_names():
    for interface, addrs in psutil.net_if_addrs().items():
        print(f"{GREEN}Interface Name: {interface}{RESET}")
        for addr in addrs:
            print(f"-> Address: {addr.address} Family: {addr.family}")
        print()

def physical_ethernet_address():
    for interface, addrs in psutil.net_if_addrs().items():
        if interface == "Ethernet":
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    return addr.address
    return None

def receive_all(sock, size):
    print("Entered receive_all")
    data = b''
    while len(data) < size:
        print("Waiting for ",str((size - len(data)))) 
        chunk = sock.recv(size - len(data))
        print("Received the chunk")
        if not chunk:
            raise EOFError("Receiving: Socket connection broken.")
        data += chunk
    return data

def send_all(sock,data):
    total_bytes_sent = 0
    while total_bytes_sent < len(data):
        sent = sock.send(data[total_bytes_sent:])
        if sent == 0:
            raise RuntimeError("Sending: Socket connection broken.")
        total_bytes_sent += sent

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
