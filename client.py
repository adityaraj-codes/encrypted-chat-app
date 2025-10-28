import customtkinter as ctk
import socket
import threading
import json
import textwrap
from crypto_utils import generate_keys, encrypt_message, decrypt_message, serialize_public_key
from cryptography.hazmat.primitives import serialization

HOST = '127.0.0.1' 
PORT = 65432

# generate keys once
private_key, public_key = generate_keys()

class ChatClient(ctk.CTk):
    def __init__(self):
        super().__init__()

        ctk.set_appearance_mode("dark")
        self.title("NOVA - Login")
        self.geometry("400x300")
        self.configure(fg_color="#121212")

        # login UI
        self.login_frame = ctk.CTkFrame(self, fg_color="#1e1e1e", corner_radius=15)
        self.login_frame.pack(expand=True, fill="both", padx=50, pady=50)

        ctk.CTkLabel(self.login_frame, text="🔐 Welcome to NOVA", font=("Arial", 20, "bold"),
                     text_color="#4CAF50").pack(pady=(20, 10))
        ctk.CTkLabel(self.login_frame, text="Enter your username", font=("Arial", 13),
                     text_color="#cccccc").pack(pady=(0, 5))
        self.username_entry = ctk.CTkEntry(self.login_frame, placeholder_text="Username",
                                           fg_color="#2c2c2c", border_color="#333333")
        self.username_entry.pack(pady=(0, 20), padx=40, fill='x')
        self.username_entry.focus()
        self.username_entry.bind("<Return>", lambda event: self.start_chat()) # Bind Enter key

        self.login_button = ctk.CTkButton(self.login_frame, text="Login",
                                          command=self.start_chat,
                                          fg_color="#3498db", hover_color="#2980b9")
        self.login_button.pack(pady=10)

        # runtime fields
        self.client_socket = None
        self.running = False
        self.username = None
        
        # Updated data structures
        self.client_data = {}      # Will store addr_str -> {"username": ..., "pem": ..., "pub_key": ...}
        self.target_address = None # This will store the addr_str of the user you want to DM

    # -------- LOGIN HANDLER --------
    def start_chat(self, *args): # Added *args to handle the event from Enter key
        uname = self.username_entry.get().strip()
        if not uname:
            self.username_entry.configure(placeholder_text="Please enter a username!")
            return
        self.username = uname

        self.login_frame.pack_forget()
        self.build_main_ui()

        # now connect to server
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client_socket.connect((HOST, PORT))
        except Exception as e:
            self.add_message_bubble(f"Error: Connection failed: {e}", sender='system')
            self.status_label.configure(text="Disconnected | Server Error", text_color="#e74c3c")
            return

        # send intro message: username::public_key_pem
        intro = f"{self.username}::{serialize_public_key(public_key)}"
        try:
            self.client_socket.sendall(intro.encode())
        except Exception as e:
            self.add_message_bubble(f"Error sending intro: {e}", sender='system')

        # start listener thread
        self.running = True
        t = threading.Thread(target=self.receive_messages, daemon=True)
        t.start()

    # Build the main chat UI 
    def build_main_ui(self):
        self.title(f"NOVA - {self.username}")
        self.geometry("800x650")
        self.configure(fg_color="#121212")

        # grid config
        self.grid_columnconfigure(0, weight=3)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)

        # main frame
        self.main_frame = ctk.CTkFrame(self, fg_color="#121212")
        self.main_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=(10, 5))
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        self.chat_header = ctk.CTkLabel(self.main_frame, text="Secure Conversation (Everyone)",
                                        font=("Arial", 16, "bold"), text_color="#ffffff",
                                        fg_color="#333333", corner_radius=8)
        self.chat_header.grid(row=0, column=0, sticky="ew", padx=5, pady=(0, 5), ipady=5)

        self.chat_scrollable_frame = ctk.CTkScrollableFrame(self.main_frame, fg_color="#121212")
        self.chat_scrollable_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=(0, 5))
        self.chat_scrollable_frame.grid_columnconfigure(0, weight=1)
        self.chat_scrollable_frame.grid_columnconfigure(1, weight=1)
        self.message_widgets = []

        # welcome system message
        self.add_message_bubble(f"Welcome {self.username}! Secure connection initializing...", sender='system')

        # users frame (right pane)
        self.users_frame = ctk.CTkFrame(self, fg_color="#1e1e1e")
        self.users_frame.grid(row=0, column=1, sticky="nsew", padx=(0, 10), pady=(10, 5))
        self.users_frame.grid_columnconfigure(0, weight=1)

        self.users_header = ctk.CTkLabel(self.users_frame, text="Active Users (1)", font=("Arial", 14, "bold"), text_color="#4CAF50")
        self.users_header.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))

        self.users_list_frame = ctk.CTkScrollableFrame(self.users_frame, fg_color="#1e1e1e", height=400)
        self.users_list_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=(0, 10))
        self.users_list_frame.grid_columnconfigure(0, weight=1)
        self.user_widgets = []

        # input frame bottom-left
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

        # status bar bottom-right
        self.status_bar = ctk.CTkFrame(self, fg_color="#1e1e1e", height=40)
        self.status_bar.grid(row=1, column=1, sticky="ew", padx=(0, 10), pady=(0, 10))
        self.status_bar.grid_columnconfigure(0, weight=1)

        self.status_label = ctk.CTkLabel(self.status_bar, text=f"Connected | Server: {HOST}:{PORT}", font=("Arial", 10), text_color="#4CAF50")
        self.status_label.grid(row=0, column=0, padx=10, pady=5, sticky="e")

        # refresh user list initially (you are the only known user until server responds)
        self.refresh_user_list()

    # --------HELPER FUNCTION--------
    def set_target(self, addr_str):
        """Sets the target for private messages."""
        if addr_str is None:
            # Broadcasting to everyone
            self.target_address = None
            self.chat_header.configure(text="Secure Conversation (Everyone)")
            
        elif addr_str in self.client_data:
            # Targeting a specific user
            self.target_address = addr_str
            username = self.client_data[addr_str]["username"]
            self.chat_header.configure(text=f"🔒 Private Chat with {username}")

    # ---------- MESSAGE FUNCTIONS ----------
    def send_message(self, *args):
        message = self.msg_entry.get().strip()
        if not message:
            return

        full_message = f"{self.username}: {message}"
        sent_ok = False

        if self.target_address:
            # --- PRIVATE MESSAGE ---
            if self.target_address not in self.client_data:
                self.add_message_bubble(f"Error: User is no longer online.", 'system')
                return
            
            try:
                target_info = self.client_data[self.target_address]
                target_key = target_info["pub_key"] # Get the loaded key object
                
                encrypted = encrypt_message(target_key, full_message)
                self.client_socket.sendall(encrypted)
                sent_ok = True
            except Exception as e:
                self.add_message_bubble(f"Error sending private message: {e}", sender='system')

        else:
            # --- BROADCAST (Everyone) ---
            if not self.client_data:
                self.add_message_bubble("No other clients online to send to.", sender='system')
                self.msg_entry.delete(0, 'end')
                return
                
            for addr_str, info in self.client_data.items():
                try:
                    encrypted = encrypt_message(info["pub_key"], full_message)
                    self.client_socket.sendall(encrypted)
                    sent_ok = True
                except Exception as e:
                    self.add_message_bubble(f"Error sending to {info['username']}: {e}", sender='system')

        if sent_ok:
            # Show our own message locally (just the message, not "Username: message")
            self.add_message_bubble(message, sender='me')

        self.msg_entry.delete(0, 'end')

    def receive_messages(self):
        while self.running:
            try:
                data = self.client_socket.recv(8192)
                if not data:
                    break

                # 1) Try decrypting as a forwarded encrypted message
                try:
                    decrypted = decrypt_message(private_key, data)
                    # decrypted should be like "username: message"
                    self.add_message_bubble(decrypted, sender='other')
                    continue
                except Exception:
                    pass

                # 2) Try parsing as a client_data JSON update
                try:
                    decoded = data.decode()
                    data_dict = json.loads(decoded)
                    # Call the RENAMED function
                    self.update_client_data(data_dict)
                    continue
                except Exception:
                    # not JSON - ignore
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
        # clear
        for widget in getattr(self, "user_widgets", []):
            widget.destroy()
        self.user_widgets.clear()

        # 1. Add "Everyone" button
        everyone_btn = ctk.CTkButton(
            self.users_list_frame, 
            text="📢 Everyone", 
            font=("Arial", 12, "bold"),
            fg_color="#333333",
            hover_color="#444444",
            command=lambda: self.set_target(None) # Set target to None
        )
        everyone_btn.pack(anchor='w', padx=10, pady=(5, 5), fill='x')
        self.user_widgets.append(everyone_btn)

        # 2. Add "You" label
        me_label = ctk.CTkLabel(self.users_list_frame, text=f"• You ({self.username})", font=("Arial", 12, "bold"), text_color="#ffffff")
        me_label.pack(anchor='w', padx=10, pady=(5, 2))
        self.user_widgets.append(me_label)

        # 3. Add other users (as buttons)
        for addr_str, info in self.client_data.items():
            username = info.get("username", "Unknown")
            
            # Use a lambda to capture the current addr_str
            user_btn = ctk.CTkButton(
                self.users_list_frame, 
                text=f"• {username}", 
                font=("Arial", 12),
                fg_color="transparent",
                hover_color="#333333",
                anchor="w", # Align text left
                command=lambda a=addr_str: self.set_target(a)
            )
            user_btn.pack(anchor='w', padx=10, pady=2, fill='x')
            self.user_widgets.append(user_btn)

        count = len(self.client_data) + 1
        self.users_header.configure(text=f"Active Users ({count})")

    def update_client_data(self, data_dict):
        """data_dict is addr_str -> {"username": ..., "pem": ...}"""
        self.client_data.clear() # Clear old data
        
        try:
            local_addr_tuple = self.client_socket.getsockname()
            local_addr_str = f"{local_addr_tuple[0]}:{local_addr_tuple[1]}"
        except:
            local_addr_str = None

        for addr_str, info in data_dict.items():
            if addr_str == local_addr_str:
                continue # Skip ourselves
            
            try:
                # Load the public key from the pem string and store it
                info["pub_key"] = serialization.load_pem_public_key(info["pem"].encode())
                self.client_data[addr_str] = info
            except Exception as e:
                print(f"Failed to load public key for {addr_str}: {e}")
        
        # Check if your target is still online
        if self.target_address and self.target_address not in self.client_data:
             self.add_message_bubble(f"Targeted user went offline. Switching to public chat.", 'system')
             self.set_target(None) # Reset to "Everyone"

        self.add_message_bubble(f"[Updated: {len(self.client_data)} other clients online]", sender='system')
        self.refresh_user_list() # Update the UI

    def add_message_bubble(self, text, sender='other'):
        color = "#2c2c2c"
        anchor = 'w'
        column = 0

        if sender == 'me':
            color = "#3498db"
            anchor = 'e'
            column = 1
        elif sender == 'system':
            color = "#1e1e1e"
            anchor = 'center'
            column = 0

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
            bubble.grid(row=len(self.message_widgets), column=column, sticky=anchor, padx=10, pady=5)

        self.message_widgets.append(bubble)
        self.chat_scrollable_frame.update_idletasks()
        try:
            self.chat_scrollable_frame._parent_canvas.yview_moveto(1.0)
        except:
            pass

    def show_crypto_details(self):
        if hasattr(self, 'details_window') and getattr(self, 'details_window', None) and self.details_window.winfo_exists():
            self.details_window.lift()
            return

        self.details_window = ctk.CTkToplevel(self)
        self.details_window.title("RSA Encryption/Decryption Details")
        self.details_window.geometry("700x500")
        self.details_window.configure(fg_color="#1e1e1e")
        self.details_window.grid_columnconfigure(0, weight=1)

        key_frame = ctk.CTkFrame(self.details_window, fg_color="#2c2c2c")
        key_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        key_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(key_frame, text="🔑 Your Local AES & RSA Keys (2048-bit)", font=("Arial", 14, "bold"), text_color="#f39c12").pack(pady=(5, 0))
        pub_key_str = serialize_public_key(public_key)

        ctk.CTkLabel(key_frame, text="Public Key (Sent to Server):", font=("Arial", 11, "bold"), text_color="#ffffff").pack(anchor='w', padx=10)
        pub_key_text = ctk.CTkTextbox(key_frame, height=100, fg_color="#121212", wrap="word", border_color="#1e1e1e")
        pub_key_text.insert("0.0", pub_key_str)
        pub_key_text.configure(state="disabled")
        pub_key_text.pack(fill='x', padx=10, pady=5)

        ctk.CTkLabel(key_frame, text="Private Key: Held Securely for Decryption. Not displayed for security.", font=("Arial", 11), text_color="#aaaaaa").pack(pady=(0, 5))

        process_frame = ctk.CTkFrame(self.details_window, fg_color="#2c2c2c")
        process_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=5)
        process_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(process_frame, text="🔒 Crypto Process Overview (AES & RSA/OAEP-SHA256)", font=("Arial", 14, "bold"), text_color="#f39c12").pack(pady=(5, 0))

        steps = [
            "1. **Key Exchange**: Client generates an AES & RSA key pair and sends its Public Key to the server.",
            "2. **ENCRYPTION**: Plaintext message -> Encrypted Bytes (recipient's public key)",
            "3. **TRANSPORT**: Encrypted Bytes -> Server (server forwards raw bytes to other clients)",
            "4. **DECRYPTION**: Received Encrypted Bytes -> Decrypted using your private key"
        ]
        for step in steps:
            ctk.CTkLabel(process_frame, text=step, font=("Arial", 12), text_color="#ffffff", justify='left').pack(anchor='w', padx=10, pady=2)

        ctk.CTkLabel(process_frame, text="Note: The server only relays the encrypted message and cannot read it.", font=("Arial", 10), text_color="#999999").pack(pady=(5, 10))

    def on_closing(self):
        self.running = False
        try:
            if self.client_socket:
                self.client_socket.shutdown(socket.SHUT_RDWR)
                self.client_socket.close()
        except:
            pass
        self.destroy()


if __name__ == "__main__":
    app = ChatClient()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()