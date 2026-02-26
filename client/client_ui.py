import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess, sys, os, threading

from .client_network import ClientNetwork
from .permissions import ask_permissions


class ClientUI:
    def __init__(self, master: tk.Tk) -> None:
        self.master = master
        master.title("Remote Client")
        master.geometry("500x400")
        master.protocol("WM_DELETE_WINDOW", self.on_close)

        self.network = ClientNetwork(self)
        self.connected = False
        self.shell_auto = tk.BooleanVar(value=True)
        self.shell_port_var = tk.IntVar(value=4444)
        self._shell_started = False
        self._shell_proc = None
        self.master.after(1200, self._tick_shell_autostart)

        self.notebook = ttk.Notebook(master)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        conn_tab = ttk.Frame(self.notebook)
        self.notebook.add(conn_tab, text="Connection")

        self.status_label = tk.Label(conn_tab, text="Status: Not connected", fg="red")
        self.status_label.pack(pady=10)

        self.info_frame = ttk.LabelFrame(conn_tab, text="Connection Info")
        self.info_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(self.info_frame, text="Server IP:").grid(row=0, column=0, sticky="w", padx=5)
        self.ip_entry = ttk.Entry(self.info_frame, width=20)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.grid(row=0, column=1, padx=5)
        tk.Label(self.info_frame, text="Shell Port:").grid(row=1, column=0, sticky="w", padx=5)
        ttk.Entry(self.info_frame, textvariable=self.shell_port_var, width=8).grid(row=1, column=1, padx=5, sticky="w")
        self.auto_chk = ttk.Checkbutton(self.info_frame, text="Auto-start Shell", variable=self.shell_auto)
        self.auto_chk.grid(row=2, column=0, columnspan=2, sticky="w", padx=5)

        btn_frame = ttk.Frame(conn_tab)
        btn_frame.pack(pady=10)

        self.connect_btn = ttk.Button(btn_frame, text="Connect", command=self.connect_to_server)
        self.connect_btn.pack(side=tk.LEFT, padx=5)

        self.disconnect_btn = ttk.Button(btn_frame, text="Disconnect", command=self.disconnect, state=tk.DISABLED)
        self.disconnect_btn.pack(side=tk.LEFT, padx=5)

        self.perms_btn = ttk.Button(conn_tab, text="Permissions", command=self.show_permissions)
        self.perms_btn.pack(pady=10)

        chat_tab = ttk.Frame(self.notebook)
        self.notebook.add(chat_tab, text="Chat")

        self.chat_display = scrolledtext.ScrolledText(chat_tab, state=tk.DISABLED)
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        chat_frame = ttk.Frame(chat_tab)
        chat_frame.pack(fill=tk.X, padx=10, pady=5)

        self.chat_entry = ttk.Entry(chat_frame)
        self.chat_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.chat_entry.bind("<Return>", self.send_chat_message)

        self.chat_send_btn = ttk.Button(chat_frame, text="Send", command=self.send_chat_message)
        self.chat_send_btn.pack(side=tk.LEFT)

    def update_chat(self, message: str) -> None:
        """Update chat display with a new message"""
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)

    def send_chat_message(self, event=None) -> None:
        """Send a chat message to the admin"""
        message = self.chat_entry.get().strip()
        if not message:
            return
            
        if not self.network.connection:
            messagebox.showwarning("Not Connected", "Please connect to a server first")
            return
            
        try:
           
            self.network.send_chat_message(message)
           
            self.update_chat(f"[You] {message}")
          
            self.chat_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {e}")

    def connect_to_server(self) -> None:
        server_ip = self.ip_entry.get().strip()
        if not server_ip:
            messagebox.showerror("Error", "Please enter a server IP address")
            return
        permissions = ask_permissions(self.master)
        if permissions:
            try:
                self.network.connect(server_ip, permissions)
                self.status_label.config(text="Status: Connected", fg="green")
                self.connect_btn.config(state=tk.DISABLED)
                self.disconnect_btn.config(state=tk.NORMAL)
                self.perms_btn.config(state=tk.DISABLED)
                self.connected = True
                self.update_chat("[System] Connected to server successfully")
            except Exception as e:
                messagebox.showerror("Connection Error", str(e))

    def disconnect(self) -> None:
        self.network.disconnect()
        self.status_label.config(text="Status: Not connected", fg="red")
        self.connect_btn.config(state=tk.NORMAL)
        self.disconnect_btn.config(state=tk.DISABLED)
        self.perms_btn.config(state=tk.NORMAL)
        self.connected = False
        self.update_chat("[System] Disconnected from server")

    def show_permissions(self) -> None:
        ask_permissions(self.master)

    
    def _tick_shell_autostart(self):
        try:
            if getattr(self, "connected", False) and not self._shell_started and self.shell_auto.get():
                self._launch_shell_client()
        finally:
            try:
                self.master.after(1500, self._tick_shell_autostart)
            except Exception:
                pass

    def _launch_shell_client(self):
        ip = self.ip_entry.get().strip() or "127.0.0.1"
        port = int(self.shell_port_var.get() or 4444)
        script = os.path.join(os.path.dirname(__file__), "shell_client.py")
        env = os.environ.copy()
        env["SHELL_SERVER_IP"] = ip
        env["SHELL_SERVER_PORT"] = str(port)
        try:
            self._shell_proc = subprocess.Popen([sys.executable, "-u", script], env=env)
            self._shell_started = True
            self.update_chat(f"[System] Auto-started shell client to {ip}:{port}")
        except Exception as e:
            try:
                self.update_chat(f"[System] Shell auto-start failed: {e}")
            except Exception:
                pass
    def on_close(self) -> None:
        try:
            self.network.disconnect()
        except Exception:
            pass
        try:
            if getattr(self, "_shell_proc", None):
                self._shell_proc.terminate()
        except Exception:
            pass
        self.master.destroy()
