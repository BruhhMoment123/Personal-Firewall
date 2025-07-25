# testserver.py
import socket

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("127.0.0.1", 5555))  # Only local connections
server.listen(1)
print("🚀 TCP Server listening on port 5555...")

while True:
    conn, addr = server.accept()
    print(f"✅ Connection from {addr}")
    conn.sendall(b"Hello from server")
    conn.close()
