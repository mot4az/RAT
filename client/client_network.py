import socket
import ssl
import struct
import threading
import subprocess
import os
import platform
import time
import json
import base64

from .client_stream import StreamSender
from . import shell_client
from common.encryption import create_ssl_context
from common.protocols import encode_message, decode_message


class ClientNetwork:
    def __init__(self, ui) -> None:
        self.ui = ui
        self.connection: ssl.SSLSocket | None = None
        self.running = False
        self.stream_sender: StreamSender | None = None
        self.permissions: dict = {"file_transfer": True}
        self.receiving_file = False
        self.file_buffer = b""
        self.file_info = {}

    
    def connect(self, server_ip: str, permissions: dict) -> None:
        self.permissions = permissions or {}
        ctx = create_ssl_context(server_side=False)
        raw = socket.create_connection((server_ip, 8443), timeout=10800)
        self.connection = ctx.wrap_socket(raw, server_hostname=None)
        self.running = True
        threading.Thread(target=self._reader, daemon=True).start()
        
        hello = f"{platform.system()} {platform.release()} | {platform.node()}"
        self._send("STATUS", hello)

    def _reader(self) -> None:
        assert self.connection is not None
        try:
            while self.running:
               
                if self.receiving_file:
                    chunk = self.connection.recv(min(4096, self.file_info["remaining"]))
                    if not chunk:
                        break
                    self.file_buffer += chunk
                    self.file_info["remaining"] -= len(chunk)
                    
                  
                    received = self.file_info["size"] - self.file_info["remaining"]
                    progress_msg = f"Receiving file: {self.file_info['name']} ({received}/{self.file_info['size']} bytes)"
                    self._ui_update_chat(f"[System] {progress_msg}")
                    
                    
                    if self.file_info["remaining"] <= 0:
                        self._save_received_file()
                        self.receiving_file = False
                        self.file_buffer = b""
                        self.file_info = {}
                    continue
                
               
                header = self.connection.recv(4)
                if not header:
                    break
                (size,) = struct.unpack("!I", header)
                data = b""
                while len(data) < size:
                    chunk = self.connection.recv(size - len(data))
                    if not chunk:
                        break
                    data += chunk
                if not data:
                    break
                mtype, content = decode_message(data)
                if mtype == "COMMAND":
                    if content.startswith("SHELL_START "):
                        try:
                            parts = content.split()
                            ip = parts[1]
                            port = int(parts[2]) if len(parts) > 2 else 4444
                        except Exception:
                            ip, port = None, 4444
                        try:
                            import threading
                            threading.Thread(target=shell_client.run, args=(ip, port), daemon=True).start()
                            self._ui_update_chat(f"[System] Starting shell client to {ip}:{port}")
                        except Exception as e:
                            self._ui_update_chat(f"[System] Shell start failed: {e}")
                    else:
                        self._handle_command(content)
                elif mtype == "CHAT":
                    self._ui_update_chat(f"[Admin] {content}")
                else:
                    pass
        except Exception as e:
            self._ui_error(f"Reader error: {e}")
        finally:
            self.disconnect()


    def _handle_command(self, cmd: str) -> None:
        try:
            if cmd.startswith("START_STREAM"):
                self._start_stream()
                return
            if cmd.startswith("STOP_STREAM"):
                self._stop_stream()
                return
            if cmd.startswith("FILE:"):

                self._handle_file_transfer(cmd)
                return
            if cmd.startswith("LISTDIR:"):
                path = cmd.split(":", 1)[1].strip() or "HOME"
                payload = self._listdir_payload(path)
                self._send("DIR_LIST", json.dumps(payload))
                return
            if cmd.startswith("READFILE:"):
                rest = cmd.split(":", 1)[1]
                path, _, maxs = rest.partition("|")
                try:
                    max_bytes = int(maxs) if maxs else 1024 * 1024
                except Exception:
                    max_bytes = 1024 * 1024
                meta = self._readfile_payload(path.strip(), max_bytes)
                self._send("FILE_CONTENT", json.dumps(meta))
                return

            if self.permissions.get("system_commands", True):
                try:

                    proc = subprocess.Popen(
                        cmd,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                    )
                    for line in proc.stdout or []:
                        self._send("CMD_OUTPUT", line.rstrip("\n"))
                except Exception as e:
                    self._send("CMD_OUTPUT", f"Error: {e}")
            else:
                self._send("CMD_OUTPUT", "System commands are not permitted.")
        except Exception as e:
            self._send("CMD_OUTPUT", f"Command error: {e}")


    def _handle_file_transfer(self, cmd: str) -> None:
        """Handle incoming file transfer from admin"""
        if not self.permissions.get("file_transfer", False):
            self._send("CHAT", "File transfer not permitted by client settings")
            return
        
        try:

            _, file_info = cmd.split(":", 1)
            filename, filesize, destination = file_info.split("|")
            destination = destination.strip()
            filesize = int(filesize)
            
            self.file_info = {
                "name": filename,
                "size": filesize,
                "remaining": filesize,
                "destination": destination
            }
            self.receiving_file = True
            self.file_buffer = b""
            
            self._ui_update_chat(f"[System] Starting file transfer: {filename} ({filesize} bytes)")
            self._send("CHAT", f"Ready to receive file: {filename}")
        except Exception as e:
            self._send("CHAT", f"File transfer error: {e}")
            self.receiving_file = False

    def _save_received_file(self) -> None:
        """Save the received file to Downloads folder"""
        try:
            
            destination = self.file_info.get("destination", os.path.expanduser("~"))
            if destination == "HOME":
                destination = os.path.expanduser("~")
            filepath = os.path.join(destination, self.file_info["name"])
            print(f"[DEBUG] Trying to save file to: {filepath}")
            
          
            base, ext = os.path.splitext(filepath)
            counter = 1
            while os.path.exists(filepath):
                filepath = f"{base}_{counter}{ext}"
                counter += 1
            
            
            with open(filepath, "wb") as f:
                f.write(self.file_buffer)
            
            self._ui_update_chat(f"[System] File saved: {filepath}")
            self._send("CHAT", f"File received and saved: {os.path.basename(filepath)}")
        except Exception as e:
            self._ui_update_chat(f"[System] Failed to save file: {e}")
            self._send("CHAT", f"Failed to save file: {e}")

    
    def _resolve_token(self, path: str) -> str:
        p = path or "HOME"
        if p == "ROOT":
            if os.name == "nt":
                
                return "ROOT"
            return "/"
        if p == "HOME":
            return os.path.expanduser("~")
        return p

    def _listdir_payload(self, path: str) -> dict:
        if not self.permissions.get("file_transfer", False):
            return {"path": path, "items": [], "error": "File access not permitted by client."}
        p = self._resolve_token(path)
        items: list[dict] = []
        try:
            if p == "ROOT" and os.name == "nt":
               
                import string
                import ctypes
                bitmask = ctypes.windll.kernel32.GetLogicalDrives()
                for i, letter in enumerate(string.ascii_uppercase):
                    if bitmask & (1 << i):
                        drive = f"{letter}:/"
                        items.append({"name": drive, "type": "dir", "size": 0, "path": drive})
                return {"path": "ROOT", "items": items}
            with os.scandir(p) as it:
                for e in it:
                    try:
                        info = e.stat(follow_symlinks=False)
                        items.append({
                            "name": e.name,
                            "type": "dir" if e.is_dir(follow_symlinks=False) else "file",
                            "size": 0 if e.is_dir(follow_symlinks=False) else int(info.st_size),
                            "mtime": int(info.st_mtime),
                            "path": os.path.join(p, e.name),
                        })
                    except Exception:
                        continue
            

            items.sort(key=lambda x: (x["type"] != "dir", x["name"].lower()))
            return {"path": p, "items": items}
        except Exception as e:
            return {"path": p, "items": [], "error": str(e)}

    def _readfile_payload(self, path: str, max_bytes: int) -> dict:
        if not self.permissions.get("file_transfer", False):
            return {"path": path, "error": "File access not permitted by client."}
        p = self._resolve_token(path)
        try:
            if os.path.isdir(p):
                return {"path": p, "error": "Path is a directory."}
            size = os.path.getsize(p)
            truncated = size > max_bytes
            with open(p, "rb") as f:
                data = f.read(min(size, max_bytes))
      
            try:
                text = data.decode("utf-8")
                return {"path": p, "kind": "text", "text": text, "truncated": truncated}
            except Exception:
                pass
          
            sig = data[:16]
            is_png = sig.startswith(b"\x89PNG")
            is_jpg = sig[:3] == b"\xff\xd8\xff"
            is_gif = sig[:6] in (b"GIF87a", b"GIF89a")
            if is_png or is_jpg or is_gif:
                return {"path": p, "kind": "image", "data": base64.b64encode(data).decode("ascii"), "truncated": truncated}
         
            import binascii
            dump = binascii.hexlify(data[:4096]).decode("ascii")
            spaced = " ".join(dump[i:i+2] for i in range(0, len(dump), 2))
            return {"path": p, "kind": "binary", "hexdump": spaced, "truncated": truncated}
        except Exception as e:
            return {"path": p, "error": str(e)}

   
    def _send(self, mtype: str, text: str) -> None:
        try:
            if self.connection:
                self.connection.sendall(encode_message(mtype, text))
        except Exception:
            pass

    def send_chat_message(self, message: str) -> None:
        """Send a chat message to the admin"""
        self._send("CHAT", message)

    def _start_stream(self) -> None:
        if self.stream_sender:
            return
        try:
            host = self.connection.getpeername()[0] if self.connection else ""
            self.stream_sender = StreamSender(host, 9999)
            self.stream_sender.start()
        except Exception as e:
            self._send("CHAT", f"Stream start error: {e}")

    def _stop_stream(self) -> None:
        try:
            if self.stream_sender:
                self.stream_sender.stop()
        finally:
            self.stream_sender = None

    def _ui_update_chat(self, text: str) -> None:
        """Update chat display in UI (thread-safe)"""
        try:
            self.ui.master.after(0, self.ui.update_chat, text)
        except Exception:
            pass

    def _ui_error(self, text: str) -> None:
        try:
            from tkinter import messagebox
            self.ui.master.after(0, lambda: messagebox.showerror("Network", text))
        except Exception:
            pass

    def disconnect(self) -> None:
        self.running = False
        if self.connection:
            try:
                self.connection.close()
            except Exception:
                pass
            self.connection = None
        if self.stream_sender:
            self.stream_sender.stop()
            self.stream_sender = None
        print("[*] Disconnected from server")

    def _keep_alive(self):
        while self.running:
            try:
                if self.connection:
                    self.connection.send(encode_message("PING", ""))
            except:
                break
            time.sleep(20)