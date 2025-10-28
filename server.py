# server.py
import socket
import threading
import json

HOST = "127.0.0.1"
PORT = 65432

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen()

clients = {}       # conn -> addr_tuple
public_keys = {}   # "ip:port" -> pem_str

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

def send_public_keys_update():
    """Send the JSON public-key registry to all connected clients."""
    try:
        payload = json.dumps(public_keys).encode()
    except Exception as e:
        print(f"[ERROR] Could not json-encode public keys: {e}")
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

    try:
        # Expect intro message: username::public_key_pem
        intro = conn.recv(8192)
        if not intro:
            conn.close()
            return

        try:
            intro_text = intro.decode()
        except:
            # If decoding fails, reject connection
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
        clients[conn] = (addr, username)
        public_keys[addr_str] = pub_pem

        print(f"{username} joined from {addr_str}")

        # notify everyone of keys update
        send_public_keys_update()

        # Now handle normal traffic — server only relays raw bytes
        while True:
            data = conn.recv(8192)
            if not data:
                break
            # Raw bytes forwarded to other clients
            broadcast_raw(data, conn)

    except Exception as e:
        print(f"[ERROR] {addr_str}: {e}")

    finally:
        # Cleanup
        if conn in clients:
            _, username = clients.pop(conn)
            print(f"{username} disconnected.")
        if addr_str in public_keys:
            public_keys.pop(addr_str, None)
        try:
            conn.close()
        except:
            pass
        send_public_keys_update()


def start():
    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()


if __name__ == "__main__":
    start()