import customtkinter as ctk
import socket
import threading
import json
import textwrap

from crypto_utils import generate_keys, encrypt_message, decrypt_message, serialize_public_key
from cryptography.hazmat.primitives import serialization

HOST = '10.204.176.8'
PORT = 65432

private_key, public_key = generate_keys()

class ChatClient(ctk.CTk):
    def __init__(self):
        super().__init__()

        ctk.set_appearance_mode("dark")
        self.title("NOVA")
        self.geometry("800x650") 
        self.configure(fg_color="#121212")

        # Configure grid for main window: 2 columns (70% for chat, 30% for users)
        self.grid_columnconfigure(0, weight=3) # Chat column
        self.grid_columnconfigure(1, weight=1) # Users column
        self.grid_rowconfigure(0, weight=1) # Main content
        self.grid_rowconfigure(1, weight=0) # Input/Status bar

        # =================================================================
        # MAIN CHAT CONTENT FRAME (Left Pane)
        # =================================================================
        self.main_frame = ctk.CTkFrame(self, fg_color="#121212")
        self.main_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=(10, 5))
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        # Chat Header
        self.chat_header = ctk.CTkLabel(self.main_frame, text="Secure Conversation", font=("Arial", 16, "bold"), text_color="#ffffff", fg_color="#333333", corner_radius=8)
        self.chat_header.grid(row=0, column=0, sticky="ew", padx=5, pady=(0, 5), ipady=5)
        
        # Scrollable Frame for Chat
        self.chat_scrollable_frame = ctk.CTkScrollableFrame(self.main_frame, fg_color="#121212")
        self.chat_scrollable_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=(0, 5))
        self.chat_scrollable_frame.grid_columnconfigure(0, weight=1)
        self.chat_scrollable_frame.grid_columnconfigure(1, weight=1)
        self.message_widgets = []
        
        # Initial system message
        self.add_message_bubble(f"Secure connection established to {HOST}:{PORT}. Start chatting!", sender='system')

        # =================================================================
        # ACTIVE USERS FRAME (Right Pane)
        # =================================================================
        self.users_frame = ctk.CTkFrame(self, fg_color="#1e1e1e")
        self.users_frame.grid(row=0, column=1, sticky="nsew", padx=(0, 10), pady=(10, 5))
        self.users_frame.grid_columnconfigure(0, weight=1)

        self.users_header = ctk.CTkLabel(self.users_frame, text="Active Users (1)", font=("Arial", 14, "bold"), text_color="#4CAF50")
        self.users_header.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        
        self.users_list_frame = ctk.CTkScrollableFrame(self.users_frame, fg_color="#1e1e1e", height=400)
        self.users_list_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=(0, 10))
        self.users_list_frame.grid_columnconfigure(0, weight=1)
        self.user_widgets = []

        # =================================================================
        # INPUT AND SEND (Bottom Left)
        # =================================================================
        self.input_frame = ctk.CTkFrame(self, fg_color="#121212")
        self.input_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        self.input_frame.grid_columnconfigure(0, weight=1)
        self.input_frame.grid_columnconfigure(1, weight=0)
        self.input_frame.grid_columnconfigure(2, weight=0)
        
        self.msg_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Type your message...", fg_color="#2c2c2c", border_color="#333333")
        self.msg_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5), pady=10)
        self.msg_entry.bind("<Return>", lambda event: self.send_message())
        
        self.send_button = ctk.CTkButton(self.input_frame, text="Send", command=self.send_message, fg_color="#3498db", hover_color="#2980b9")
        self.send_button.grid(row=0, column=1, padx=(5, 5), pady=10)
        
        self.details_button = ctk.CTkButton(self.input_frame, text="E/D Details", command=self.show_crypto_details, fg_color="#f39c12", hover_color="#e67e22")
        self.details_button.grid(row=0, column=2, padx=(0, 0), pady=10) 
        
        # =================================================================
        # STATUS BAR (Bottom Right - Under User List)
        # =================================================================
        self.status_bar = ctk.CTkFrame(self, fg_color="#1e1e1e", height=40)
        self.status_bar.grid(row=1, column=1, sticky="ew", padx=(0, 10), pady=(0, 10))
        self.status_bar.grid_columnconfigure(0, weight=1)

        self.status_label = ctk.CTkLabel(self.status_bar, text=f"Connected | Server: {HOST}:{PORT}", font=("Arial", 10), text_color="#4CAF50")
        self.status_label.grid(row=0, column=0, padx=10, pady=5, sticky="e")

        # ===== Socket Setup =====
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            self.client_socket.connect((HOST, PORT))
        except ConnectionRefusedError:
            self.add_message_bubble("Error: Connection refused. Ensure server is running.", sender='system')
            self.status_label.configure(text="Disconnected | Server Error", text_color="#e74c3c")
            return

        serialized_pub = serialize_public_key(public_key)
        self.client_socket.send(serialized_pub.encode())

        self.clients_public_keys = {}

        self.running = True
        thread = threading.Thread(target=self.receive_messages)
        thread.daemon = True
        thread.start()

        self.refresh_user_list() # Initial user list (just 'me')

    def send_message(self, *args):
        message = self.msg_entry.get()
        if not message.strip():
            return

        if not self.clients_public_keys:
            self.add_message_bubble("No other clients online to send to.", sender='system')
            self.msg_entry.delete(0, 'end')
            return

        # Encrypt and send message to every *other* client
        sent_ok = False
        for addr, pub_key in self.clients_public_keys.items():
            try:
                encrypted_msg = encrypt_message(pub_key, message)
                self.client_socket.send(encrypted_msg)
                sent_ok = True
            except Exception as e:
                self.add_message_bubble(f"Error encrypting/sending to {addr}: {e}", sender='system')

        if sent_ok:
            # Display the message locally
            self.add_message_bubble(message, sender='me')
        
        self.msg_entry.delete(0, 'end')

    def receive_messages(self):
        while self.running:
            try:
                data = self.client_socket.recv(8192) 
                if not data:
                    break

                # 1. Attempt Decryption
                try:
                    decrypted_msg = decrypt_message(private_key, data)
                    self.add_message_bubble(decrypted_msg, sender='other')
                
                # 2. Assume it's the JSON Key Update
                except Exception:
                    try:
                        keys_dict = json.loads(data.decode())
                        self.update_clients_public_keys(keys_dict)
                    except:
                        # print(f"Received unrecognized data: {data}")
                        pass
                        
            except ConnectionResetError:
                self.add_message_bubble("Server disconnected.", sender='system')
                self.status_label.configure(text="Disconnected | Server Error", text_color="#e74c3c")
                self.running = False
                break
            except Exception as e:
                self.add_message_bubble(f"Receive Error: {e}", sender='system')
                self.status_label.configure(text="Disconnected | Client Error", text_color="#e74c3c")
                self.running = False
                break

    def refresh_user_list(self):
        """Clears and re-populates the Active Users list."""
        
        # Clear existing widgets
        for widget in self.user_widgets:
            widget.destroy()
        self.user_widgets.clear()
        
        local_addr_tuple = self.client_socket.getsockname()
        local_addr_str = f"{local_addr_tuple[0]}:{local_addr_tuple[1]}"
        
        # Add 'You'
        me_label = ctk.CTkLabel(self.users_list_frame, text=f"• You ({local_addr_str})", font=("Arial", 12, "bold"), text_color="#ffffff")
        me_label.pack(anchor='w', padx=10, pady=(5, 2))
        self.user_widgets.append(me_label)
        
        # Add other clients
        for addr_str in self.clients_public_keys.keys():
            user_label = ctk.CTkLabel(self.users_list_frame, text=f"• Other Client ({addr_str})", font=("Arial", 12), text_color="#cccccc")
            user_label.pack(anchor='w', padx=10, pady=2)
            self.user_widgets.append(user_label)
            
        # Update header count
        count = len(self.clients_public_keys) + 1
        self.users_header.configure(text=f"Active Users ({count})")


    def update_clients_public_keys(self, keys_dict):
        """Processes the received dictionary of public keys from the server."""
        self.clients_public_keys.clear()
        
        local_addr_tuple = self.client_socket.getsockname()
        local_addr_str = f"{local_addr_tuple[0]}:{local_addr_tuple[1]}"
        
        for addr_str, key_str in keys_dict.items():
            if addr_str != local_addr_str:
                try:
                    pub_key = serialization.load_pem_public_key(key_str.encode())
                    self.clients_public_keys[addr_str] = pub_key
                except Exception as e:
                    print(f"Failed to load public key for {addr_str}: {e}")

        self.add_message_bubble(f"[Updated: {len(self.clients_public_keys)} other clients online]", sender='system')
        self.refresh_user_list() # Update the UI list

    def add_message_bubble(self, text, sender='other'):
        color = "#2c2c2c"
        anchor = 'w'
        column = 0

        if sender == 'me':
            color = "#3498db" # Blue for me
            anchor = 'e'
            column = 1
        elif sender == 'system':
            color = "#1e1e1e"
            anchor = 'center'
            column = 0
            
        # Use textwrap to ensure long messages fit
        wrapped_text = "\n".join(textwrap.wrap(text, width=45)) 

        if sender == 'system':
            bubble = ctk.CTkFrame(self.chat_scrollable_frame, fg_color=color, corner_radius=15)
            bubble.grid(row=len(self.message_widgets), column=0, columnspan=2, sticky='ew', padx=10, pady=5)
            label = ctk.CTkLabel(bubble, text=wrapped_text, text_color="#ffffff", font=("Arial", 11), justify='center')
            label.pack(padx=10, pady=3)
        else:
            bubble = ctk.CTkFrame(self.chat_scrollable_frame, fg_color=color, corner_radius=15)
            label = ctk.CTkLabel(bubble, text=wrapped_text, text_color="#ffffff", font=("Arial", 13), justify='left')
            label.pack(padx=10, pady=5)
            # The sticky anchor changes based on who sent it
            bubble.grid(row=len(self.message_widgets), column=column, sticky=anchor, padx=10, pady=5)


        self.message_widgets.append(bubble)

        self.chat_scrollable_frame.update_idletasks()
        self.chat_scrollable_frame._parent_canvas.yview_moveto(1.0)
        
    def show_crypto_details(self):
        """Opens a new window to show RSA key and crypto process details."""
        
        # Prevent opening multiple windows
        if hasattr(self, 'details_window') and self.details_window.winfo_exists():
            self.details_window.lift()
            return
            
        # 1. Setup the Toplevel Window
        self.details_window = ctk.CTkToplevel(self)
        self.details_window.title("RSA Encryption/Decryption Details")
        self.details_window.geometry("700x500")
        self.details_window.configure(fg_color="#1e1e1e")
        
        self.details_window.grid_columnconfigure(0, weight=1)
        
        # 2. Display Local RSA Key
        key_frame = ctk.CTkFrame(self.details_window, fg_color="#2c2c2c")
        key_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        key_frame.grid_columnconfigure(0, weight=1)
        
        ctk.CTkLabel(key_frame, text="🔑 Your Local RSA Keys (2048-bit)", font=("Arial", 14, "bold"), text_color="#f39c12").pack(pady=(5, 0))
        
        pub_key_str = serialize_public_key(public_key)
        
        ctk.CTkLabel(key_frame, text="Public Key (Sent to Server):", font=("Arial", 11, "bold"), text_color="#ffffff").pack(anchor='w', padx=10)
        pub_key_text = ctk.CTkTextbox(key_frame, height=100, fg_color="#121212", wrap="word", border_color="#1e1e1e")
        pub_key_text.insert("0.0", pub_key_str)
        pub_key_text.configure(state="disabled")
        pub_key_text.pack(fill='x', padx=10, pady=5)
        
        ctk.CTkLabel(key_frame, text="Private Key: Held Securely for Decryption. Not displayed for security.", font=("Arial", 11), text_color="#aaaaaa").pack(pady=(0, 5))

        # 3. Encryption/Decryption Process Visualization
        process_frame = ctk.CTkFrame(self.details_window, fg_color="#2c2c2c")
        process_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=5)
        process_frame.grid_columnconfigure(0, weight=1)
        
        ctk.CTkLabel(process_frame, text="🔒 Crypto Process Overview (RSA/OAEP-SHA256)", font=("Arial", 14, "bold"), text_color="#f39c12").pack(pady=(5, 0))

        # A simple, static visualization flow.
        steps = [
            "1. **Key Exchange**: Client generates an RSA key pair and sends its Public Key to the server.",
            "2. **ENCRYPTION**: Plaintext message $\\xrightarrow{\\text{Other Client's Public Key (RSA)}}$ Encrypted Bytes",
            "3. **TRANSPORT**: Encrypted Bytes $\\xrightarrow{\\text{Server Broadcast}}$ Other Clients",
            "4. **DECRYPTION**: Received Encrypted Bytes $\\xrightarrow{\\text{Your Private Key (RSA)}}$ Decrypted Plaintext"
        ]

        for step in steps:
            # Need to manually parse for LaTeX-like text if we want mathematical notation (ctk doesn't support true LaTeX)
            # For simplicity, we'll keep it as text in this example.
            ctk.CTkLabel(process_frame, text=step, font=("Arial", 12), text_color="#ffffff", justify='left').pack(anchor='w', padx=10, pady=2)
            
        ctk.CTkLabel(process_frame, text="Note: The server only relays the encrypted message and cannot read it.", font=("Arial", 10), text_color="#999999").pack(pady=(5, 10))


    def on_closing(self):
        self.running = False
        try:
            # Send a closing signal before closing the socket
            self.client_socket.shutdown(socket.SHUT_RDWR)
            self.client_socket.close()
        except:
            pass
        self.destroy()


if __name__ == "__main__":
    app = ChatClient()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()