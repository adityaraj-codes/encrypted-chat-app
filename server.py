import socket
import threading
import json
import time 

HOST = '0.0.0.0'
PORT = 65432

clients = {}  

def broadcast(message, sender_socket):
    """Sends the encrypted message to all clients except the sender."""
    clients_to_remove = []
    
    for client in list(clients.keys()): 
        if client != sender_socket:
            try:
                client.send(message)
            except:
                clients_to_remove.append(client)
    
    for client in clients_to_remove:
        if client in clients:
            print(f"Error sending to {clients[client]['addr']}, removing client.")
            client.close()
            del clients[client]
            send_keys_update() 

def send_keys_update():
    """Compiles the list of current clients' public keys and broadcasts it to all of them."""
    keys = {
        f"{info['addr'][0]}:{info['addr'][1]}": info['public_key'] 
        for info in clients.values() 
        if info.get('addr') 
    }
    keys_json = json.dumps(keys).encode()
    
    for client in list(clients.keys()): 
        try:
            client.send(keys_json)
        except Exception as e:
            print(f"Failed to send key update to {clients.get(client, {}).get('addr', 'Unknown')}: {e}")
            client.close()
            if client in clients:
                del clients[client]


def handle_client(client_socket):
    try:
        # 1. Receive Public Key (First Message)
        pubkey_data = client_socket.recv(4096).decode()
        
        client_address = client_socket.getpeername() 
        clients[client_socket] = {'public_key': pubkey_data, 'addr': client_address}
        print(f"Received public key from {client_address}")

        # 2. Update all clients with the new key list
        send_keys_update()

        # 3. Handle Chat Messages
        while True:
            message = client_socket.recv(8192) 
            if not message:
                break
            
            # Message is an encrypted byte string, broadcast it as is
            broadcast(message, client_socket)

    except Exception as e:
        if client_socket in clients:
            print(f"Error for {clients[client_socket]['addr']}: {e}")
    
    finally:
        if client_socket in clients:
            addr_info = clients[client_socket]['addr']
            print(f"Connection closed {addr_info}")
            del clients[client_socket]
            client_socket.close()
            send_keys_update()
        else:
            client_socket.close()


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # CORRECTION for WinError 10048: Allows the socket address to be reused immediately.
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
    
    try:
        server.bind((HOST, PORT))
    except OSError as e:
        print(f"\n[CRITICAL ERROR] Could not bind to {HOST}:{PORT}. ({e})")
        print("Please check if another server instance is running or if the port is in use.")
        return

    server.listen()
    print(f"Server started on {HOST}:{PORT}")
    print("Waiting for connections...")

    while True:
        client_socket, addr = server.accept()
        print(f"New connection from {addr}")
        thread = threading.Thread(target=handle_client, args=(client_socket,))
        thread.daemon = True 
        thread.start()

if __name__ == "__main__":
    start_server()