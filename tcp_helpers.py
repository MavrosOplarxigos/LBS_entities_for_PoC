import socket

def receive_all(sock, size):
    data = b''
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("Socket connection closed prematurely.")
        data += chunk
    return data

def close_connection(client_socket, client_address):
    print(f"Connection with {client_address} closed.")
    client_socket.close()