from pydivert import WinDivert

with WinDivert("true") as w:
    print("Listening for packets...")
    for i in range(10):
        packet = w.recv()
        print(f"{packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port} ({packet.protocol})")
