import socket
import threading
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import sys

def get_local_ip():
    """
    Returns a reasonable LAN IP address for this machine by creating a UDP
    socket to a public IP (no packet is actually sent). Falls back to localhost.
    This approach works well when the machine has multiple interfaces (en0/en1).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Use a public DNS address; no traffic is sent, it's only to determine the outbound IP.
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        # fallback, may return '127.0.0.1' if truly nothing else works
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

class PeerChat:
    def __init__(self, master):
        self.master = master
        master.title("P2P Chat — Auto IP & Port")

        # Top frame: info
        info_frame = tk.Frame(master)
        info_frame.pack(fill=tk.X, padx=8, pady=(8,0))

        self.local_ip = get_local_ip()

        self.own_label = tk.Label(info_frame, text=f"My IP: {self.local_ip}")
        self.own_label.pack(side=tk.LEFT)

        self.own_port_var = tk.StringVar(value="(starting...)")
        self.own_port_label = tk.Label(info_frame, textvariable=self.own_port_var)
        self.own_port_label.pack(side=tk.LEFT, padx=(10,0))

        # Chat box
        self.chat_box = ScrolledText(master, wrap=tk.WORD, width=60, height=20)
        self.chat_box.pack(padx=8, pady=8)
        self.chat_box.config(state=tk.DISABLED)

        # Peer entry frame
        peer_frame = tk.Frame(master)
        peer_frame.pack(fill=tk.X, padx=8, pady=(0,8))

        tk.Label(peer_frame, text="Peer IP:").grid(row=0, column=0, sticky="w")
        self.ip_entry = tk.Entry(peer_frame, width=20)
        self.ip_entry.grid(row=0, column=1, sticky="w", padx=(4,12))

        tk.Label(peer_frame, text="Peer Port:").grid(row=0, column=2, sticky="w")
        self.port_entry = tk.Entry(peer_frame, width=8)
        self.port_entry.grid(row=0, column=3, sticky="w", padx=(4,12))

        # Quick-fill button to copy my address into peer fields (handy for local loopback tests)
        copy_btn = tk.Button(peer_frame, text="Copy my addr → peer", command=self.copy_my_address)
        copy_btn.grid(row=0, column=4)

        # Input + send
        input_frame = tk.Frame(master)
        input_frame.pack(fill=tk.X, padx=8, pady=(0,8))

        self.entry = tk.Entry(input_frame)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,8))
        self.entry.bind("<Return>", lambda e: self.send_message())

        self.send_btn = tk.Button(input_frame, text="Send", width=10, command=self.send_message)
        self.send_btn.pack(side=tk.LEFT)

        # Create server socket and start listening thread (bind to 0.0.0.0 on ephemeral port)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Allow quick restarts during development
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("0.0.0.0", 0))   # 0 => OS picks an available port
        self.server_port = self.server.getsockname()[1]
        self.own_port_var.set(f"My Port: {self.server_port}")
        self.server.listen(5)

        self.append_chat(f"[Server listening on {self.local_ip}:{self.server_port}]")

        server_thread = threading.Thread(target=self.server_loop, daemon=True)
        server_thread.start()

    def copy_my_address(self):
        """Put this peer's IP and port into the peer entry fields (convenience)."""
        self.ip_entry.delete(0, tk.END)
        self.ip_entry.insert(0, self.local_ip)
        self.port_entry.delete(0, tk.END)
        self.port_entry.insert(0, str(self.server_port))

    def append_chat(self, text):
        """Thread-safe append to scrolled text using after()"""
        def _append():
            self.chat_box.config(state=tk.NORMAL)
            self.chat_box.insert(tk.END, text + "\n")
            self.chat_box.config(state=tk.DISABLED)
            self.chat_box.yview(tk.END)
        self.master.after(0, _append)

    def server_loop(self):
        """Accept incoming connections, read one message, display it, send a response, close."""
        while True:
            try:
                conn, addr = self.server.accept()
                with conn:
                    try:
                        data = conn.recv(4096)
                    except Exception as e:
                        self.append_chat(f"[Server] recv error: {e}")
                        continue

                    if not data:
                        continue
                    msg = data.decode(errors="replace")
                    self.append_chat(f"Peer {addr[0]}:{addr[1]} says: {msg}")

                    # simple ACK/response
                    response = f"Received: {msg}"
                    try:
                        conn.sendall(response.encode())
                    except Exception as e:
                        self.append_chat(f"[Server] send error: {e}")
            except Exception as e:
                # Non-fatal server accept error (socket closed etc)
                self.append_chat(f"[Server] accept error: {e}")
                break

    def send_message(self):
        """Connects to the peer, sends a message, waits for a response, displays it."""
        message = self.entry.get().strip()
        if not message:
            return

        peer_ip = self.ip_entry.get().strip()
        peer_port_str = self.port_entry.get().strip()

        if not peer_ip or not peer_port_str:
            self.append_chat("[Error] Enter peer IP and peer port.")
            return

        try:
            peer_port = int(peer_port_str)
        except ValueError:
            self.append_chat("[Error] Peer port must be an integer.")
            return

        # show our outgoing message
        self.append_chat(f"You -> {peer_ip}:{peer_port} : {message}")

        # Do the network operation in a background thread so GUI doesn't block
        t = threading.Thread(target=self._do_send, args=(peer_ip, peer_port, message), daemon=True)
        t.start()

        self.entry.delete(0, tk.END)

    def _do_send(self, peer_ip, peer_port, message):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)  # don't hang forever
                s.connect((peer_ip, peer_port))
                s.sendall(message.encode())

                # wait for response
                try:
                    resp = s.recv(4096)
                    if resp:
                        self.append_chat(f"Response from {peer_ip}:{peer_port} : {resp.decode(errors='replace')}")
                    else:
                        self.append_chat(f"[Warning] No response from {peer_ip}:{peer_port}")
                except socket.timeout:
                    self.append_chat(f"[Error] Timeout waiting for response from {peer_ip}:{peer_port}")
        except ConnectionRefusedError:
            self.append_chat(f"[Error] Connection refused by {peer_ip}:{peer_port}")
        except OSError as e:
            self.append_chat(f"[Error] {e}")
        except Exception as e:
            self.append_chat(f"[Error] {e}")

def main():
    root = tk.Tk()
    # If macOS sometimes needs idletasks: uncomment the two lines below.
    # root.update_idletasks()
    # root.after(50, lambda: None)

    app = PeerChat(root)
    root.mainloop()

if __name__ == "__main__":
    main()
