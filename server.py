import socket
import threading
import json

HOST = "0.0.0.0"
PORT = 65432

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen()

clients = {}       # conn -> addr_str
client_data = {}   # addr_str -> {"username": str, "pem": str}

print(f"[LISTENING] Server running on {HOST}:{PORT}")

def broadcast_raw(data: bytes, sender_conn):
    """Forward raw bytes to all clients except the sender."""
    for client in list(clients.keys()):
        if client is sender_conn:
            continue
        try:
            client.sendall(data)
        except Exception as e:
            print(f"[ERROR] Sending to {clients[client]}: {e}")
            try:
                client.close()
            except:
                pass
            clients.pop(client, None)

def send_client_data_update():
    """Send the JSON client_data registry to all connected clients."""
    try:
        payload = json.dumps(client_data).encode() # Send client_data
    except Exception as e:
        print(f"[ERROR] Could not json-encode client data: {e}")
        return

    for client in list(clients.keys()):
        try:
            client.sendall(payload)
        except Exception as e:
            print(f"[ERROR] Failed to send keys update to {clients[client]}: {e}")
            try:
                client.close()
            except:
                pass
            clients.pop(client, None)

def handle_client(conn, addr):
    addr_str = f"{addr[0]}:{addr[1]}"
    print(f"[NEW CONNECTION] {addr_str}")
    username = "Unknown" # Default

    try:
        intro = conn.recv(8192)
        if not intro:
            conn.close()
            return

        try:
            intro_text = intro.decode()
        except:
            print(f"[INVALID INTRO] {addr_str} (not UTF-8)")
            conn.close()
            return

        if "::" not in intro_text:
            print(f"[INVALID INTRO FORMAT] {addr_str}: {intro_text[:60]!r}")
            conn.close()
            return

        username, pub_pem = intro_text.split("::", 1)
        username = username.strip()
        pub_pem = pub_pem.strip()

        # Store client
        clients[conn] = addr_str # Map connection to its address string
        client_data[addr_str] = {"username": username, "pem": pub_pem} # Store user data by address

        print(f"{username} joined from {addr_str}")

        send_client_data_update() # notify everyone

        while True:
            data = conn.recv(8192)
            if not data:
                break
            broadcast_raw(data, conn)

    except Exception as e:
        print(f"[ERROR] {addr_str} ({username}): {e}")

    finally:
        # Cleanup
        if conn in clients:
            addr_str_to_remove = clients.pop(conn)
            if addr_str_to_remove in client_data:
                # Get username from the dict before deleting
                username = client_data.pop(addr_str_to_remove)["username"]
                print(f"{username} disconnected.")
        try:
            conn.close()
        except:
            pass
        send_client_data_update() # Notify everyone of the departure


def start():
    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()


if __name__ == "__main__":
    start()