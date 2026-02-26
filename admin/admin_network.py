import socket
import ssl
import struct
import threading
import time
import json

from common.encryption import create_ssl_context
from common.protocols import encode_message, decode_message


class AdminNetwork:
    def __init__(self, dashboard) -> None:
        self.dashboard = dashboard
        self.connected_clients: dict[str, dict] = {}
        self.server_running = False
        self.server_socket: socket.socket | None = None

        # Start TLS server on init (bind 0.0.0.0:8443)
        self._start_server()

   
    def _start_server(self, host: str = "0.0.0.0", port: int = 8443) -> None:
        ctx = create_ssl_context(server_side=True)
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_sock.bind((host, port))
        raw_sock.listen(5)
        self.server_socket = ctx.wrap_socket(raw_sock, server_side=True)
        self.server_running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()
        print(f"[*] Admin TLS server listening on {host}:{port}")

    def _accept_loop(self) -> None:
        assert self.server_socket is not None
        while self.server_running:
            try:
                conn, addr = self.server_socket.accept()
                client_id = f"{addr[0]}:{addr[1]}"
                self.connected_clients[client_id] = {"id": client_id, "socket": conn, "addr": addr, "status": "connected", "streaming": False}
                threading.Thread(target=self._client_reader, args=(client_id,), daemon=True).start()
                print(f"[+] Client connected: {client_id}")
            except Exception:
                if self.server_running:
                    time.sleep(0.1)

    def _client_reader(self, client_id: str) -> None:
        conn = self.connected_clients.get(client_id, {}).get("socket")
        if not conn:
            return
        try:
            buf = b""
            while self.server_running:
                
                header = conn.recv(4)
                if not header:
                    break
                (size,) = struct.unpack("!I", header)
                data = b""
                while len(data) < size:
                    chunk = conn.recv(size - len(data))
                    if not chunk:
                        break
                    data += chunk
                if not data:
                    break
                mtype, content = decode_message(data)
                if mtype is None:
                    continue
                self._process_message(client_id, mtype, content)
        except Exception as e:
            print(f"Reader error {client_id}: {e}")
        finally:
            self.disconnect_client(client_id)

    def _process_message(self, client_id: str, message_type: str, content: str) -> None:
        try:
            if message_type == "CHAT":
                self._ui(self.dashboard.update_chat, f"[{client_id}] {content}")
            elif message_type == "CMD_OUTPUT":
                ts = time.strftime("%H:%M:%S", time.localtime())
                self._ui(self.dashboard.update_command_output, f"[{ts}] {content}")
            elif message_type == "STATUS":
                self.connected_clients[client_id]["status"] = content
            elif message_type == "DIR_LIST":
                payload = json.loads(content)
                path = payload.get("path", "")
                items = payload.get("items", [])
                error = payload.get("error")
                self._ui(self.dashboard.fileexplorer_update_dir, client_id, path, items, error)
            elif message_type == "FILE_CONTENT":
                meta = json.loads(content)
                meta.setdefault("path", "")
                self._ui(self.dashboard.fileexplorer_update_file, client_id, meta)
            else:
                
                self._ui(self.dashboard.update_chat, f"[{client_id}] <{message_type}> {content}")
        except Exception as e:
            print(f"Process message error: {e}")

    def _ui(self, fn, *args):
        try:
            self.dashboard.master.after(0, fn, *args)
        except Exception:
            pass

 
    def send_command(self, client_id: str, command: str) -> None:
        conn = self.connected_clients.get(client_id, {}).get("socket")
        if not conn:
            return
        try:
            conn.sendall(encode_message("COMMAND", command))
        except Exception as e:
            print(f"Send command error to {client_id}: {e}")
            self.disconnect_client(client_id)

    def send_chat(self, client_id: str, message: str) -> None:
        conn = self.connected_clients.get(client_id, {}).get("socket")
        if not conn:
            return
        try:
            conn.sendall(encode_message("CHAT", message))
        except Exception:
            self.disconnect_client(client_id)

    def send_raw(self, client_id: str, data: bytes) -> None:
        conn = self.connected_clients.get(client_id, {}).get("socket")
        if not conn:
            return
        try:
            conn.sendall(data)
        except Exception:
            self.disconnect_client(client_id)

   
    def request_list_dir(self, client_id: str, path: str) -> None:
        self.send_command(client_id, f"LISTDIR:{path}")

    def request_read_file(self, client_id: str, path: str, max_bytes: int = 1024 * 1024) -> None:
        self.send_command(client_id, f"READFILE:{path}|{max_bytes}")

   
    def disconnect_client(self, client_id: str) -> None:
        info = self.connected_clients.get(client_id)
        if not info:
            return
        try:
            try:
                info["socket"].close()
            except Exception:
                pass
        finally:
            self.connected_clients.pop(client_id, None)
            print(f"[-] Disconnected client {client_id}")

    def stop_server(self) -> None:
        self.server_running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        for cid in list(self.connected_clients.keys()):
            self.disconnect_client(cid)
        print("[*] Admin server stopped")
