# testfirewall_bypass.py
import socket
import threading

def server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 5555))
    s.listen(1)
    print("✅ Server started on 127.0.0.1:5555")
    while True:
        conn, addr = s.accept()
        print(f"📥 Connected from {addr}")
        conn.sendall(b"Test OK")
        conn.close()

def client():
    try:
        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c.connect(('127.0.0.1', 5555))
        print("📤 Connected to server!")
        msg = c.recv(1024)
        print(f"📨 Received: {msg.decode()}")
        c.close()
    except Exception as e:
        print(f"❌ Client error: {e}")

t = threading.Thread(target=server, daemon=True)
t.start()

input("🟡 Press Enter to run client...\n")
client()

