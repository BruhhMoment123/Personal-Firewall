# client.py
import socket

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    client.connect(("127.0.0.1", 5555))
    msg = client.recv(1024)
    print(f"📨 Received: {msg.decode()}")
except Exception as e:
    print(f"❌ Connection failed: {e}")
finally:
    client.close()
