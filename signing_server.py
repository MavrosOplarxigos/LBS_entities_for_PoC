import socket
import threading
from P2P_relay_server import client_hello

FWD_SERVER_PORT = 50003

def protocol(client_socket, client_address):

    print(f"Accepted connection from {client_address}")
    # Setting a timeout for the socket: this means that if 60 seconds have passed
    # and we haven't heard back from the client we will close the connection.
    client_socket.settimeout(60)

    # Client Hello
    client_certificate, valid_message = client_hello(client_socket,client_address)
    if not valid_message:
        close_connection(client_socket,client_address)
        return
    
    # Server Hello 


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
