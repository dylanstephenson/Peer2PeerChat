import socket
import threading
import tkinter as tk
from tkinter import scrolledtext

class PeerChat:
    def __init__(self, master):
        self.master = master
        self.master.title("P2P Chat")

        # ------------------------------
        # GUI Layout
        # ------------------------------
        self.chat_box = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=50, height=20)
        self.chat_box.pack(pady=10)
        self.chat_box.config(state=tk.DISABLED)

        self.entry = tk.Entry(master, width=40)
        self.entry.pack(side=tk.LEFT, padx=10)

        self.send_btn = tk.Button(master, text="Send", command=self.send_message)
        self.send_btn.pack(side=tk.LEFT)

        # Connection fields
        self.ip_label = tk.Label(master, text="Peer IP:")
        self.ip_label.pack()

        self.ip_entry = tk.Entry(master)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.pack()

        self.port_label = tk.Label(master, text="Peer Port:")
        self.port_label.pack()

        self.port_entry = tk.Entry(master)
        self.port_entry.insert(0, "5001")
        self.port_entry.pack()

        # Start server thread
        self.server_port = 5001  # each peer can change manually or run on separate machines
        server_thread = threading.Thread(target=self.server_loop)
        server_thread.daemon = True
        server_thread.start()

    # ------------------------------
    # Server (listen for incoming messages)
    # ------------------------------
    def server_loop(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("0.0.0.0", self.server_port))
        server.listen(5)

        self.append_chat(f"[Server listening on port {self.server_port}]")

        while True:
            conn, addr = server.accept()
            message = conn.recv(1024).decode()

            # Display incoming request
            self.append_chat(f"Peer says: {message}")

            # Send back a response
            response = f"Received: {message}"
            conn.send(response.encode())
            conn.close()

    # ------------------------------
    # Client (send outbound message)
    # ------------------------------
    def send_message(self):
        message = self.entry.get()
        if not message:
            return

        peer_ip = self.ip_entry.get()
        peer_port = int(self.port_entry.get())

        # Display our message
        self.append_chat(f"You: {message}")

        # Send to peer
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_ip, peer_port))
            sock.send(message.encode())

            # Receive response
            response = sock.recv(1024).decode()
            self.append_chat(f"Peer response: {response}")

            sock.close()
        except Exception as e:
            self.append_chat(f"[Error] {e}")

        self.entry.delete(0, tk.END)

    # ------------------------------
    # Utility: Append chat text
    # ------------------------------
    def append_chat(self, text):
        self.chat_box.config(state=tk.NORMAL)
        self.chat_box.insert(tk.END, text + "\n")
        self.chat_box.config(state=tk.DISABLED)
        self.chat_box.yview(tk.END)

# Launch app
root = tk.Tk()
app = PeerChat(root)
root.mainloop()
