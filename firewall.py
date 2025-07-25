import json
import os
import threading
import time
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from pydivert import WinDivert

RULES_FILE = "rules.json"

# ---------------------- Load Rules ----------------------
def load_rules():
    if not os.path.exists(RULES_FILE):
        return {"block_ips": [], "block_ports": []}
    with open(RULES_FILE, "r") as f:
        return json.load(f)

def save_rules(rules):
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=4)

rules = load_rules()
block_ips = rules["block_ips"]
block_ports = rules["block_ports"]

# ---------------------- GUI ----------------------
root = tk.Tk()
root.title("Mini Firewall")
root.geometry("1000x600")
root.minsize(1000, 600)

# Control Frame
frame_ctrl = tk.Frame(root)
frame_ctrl.pack(pady=10)

btn_start = tk.Button(frame_ctrl, text="Start Firewall")
btn_start.grid(row=0, column=0, padx=5)
btn_stop = tk.Button(frame_ctrl, text="Stop Firewall")
btn_stop.grid(row=0, column=1, padx=5)

status_label = tk.Label(frame_ctrl, text="Status: Stopped", fg="red")
status_label.grid(row=0, column=2, padx=10)

# Rule Management Frame
frame_rules = tk.Frame(root)
frame_rules.pack(pady=5)

listbox_ips = tk.Listbox(frame_rules, height=5)
listbox_ips.grid(row=0, column=0, padx=5)
listbox_ports = tk.Listbox(frame_rules, height=5)
listbox_ports.grid(row=0, column=1, padx=5)

btn_add_ip = tk.Button(frame_rules, text="Add Block IP")
btn_add_ip.grid(row=1, column=0, pady=5)
btn_add_port = tk.Button(frame_rules, text="Add Block Port")
btn_add_port.grid(row=1, column=1, pady=5)

btn_remove_ip = tk.Button(frame_rules, text="Remove IP")
btn_remove_ip.grid(row=2, column=0, pady=5)
btn_remove_port = tk.Button(frame_rules, text="Remove Port")
btn_remove_port.grid(row=2, column=1, pady=5)

# Packet Log Treeview
columns = ("Time", "Direction", "Protocol", "Src IP", "Src Port", "Dst IP", "Dst Port", "Size", "Status")
packet_log = ttk.Treeview(root, columns=columns, show="headings", height=15)
for col in columns:
    packet_log.heading(col, text=col)
    packet_log.column(col, width=100, anchor="center")
packet_log.pack(fill="both", expand=True)

# ---------------------- Logic ----------------------
def update_lists():
    listbox_ips.delete(0, tk.END)
    listbox_ports.delete(0, tk.END)
    for ip in block_ips:
        listbox_ips.insert(tk.END, ip)
    for port in block_ports:
        listbox_ports.insert(tk.END, port)

update_lists()

firewall_running = False
sniff_thread = None

def update_packet_log_row(values, tag):
    packet_log.insert("", "end", values=values, tags=(tag,))
    packet_log.yview_moveto(1)
    if len(packet_log.get_children()) > 300:
        packet_log.delete(packet_log.get_children()[0])

def sniff_packets():
    global firewall_running
    try:
        with WinDivert("true") as w:
            while firewall_running:
                packet = w.recv()
                direction = "Outgoing" if packet.is_outbound else "Incoming"
                protocol = str(packet.protocol)
                src_ip, dst_ip = packet.src_addr, packet.dst_addr
                src_port, dst_port = packet.src_port, packet.dst_port
                size = len(packet.raw)
                time_now = time.strftime("%H:%M:%S")

                blocked = (
                    src_ip in block_ips or
                    dst_ip in block_ips or
                    src_port in block_ports or
                    dst_port in block_ports
                )

                if blocked:
                    status = "Blocked"
                    tag = "blocked"
                else:
                    status = "Allowed"
                    tag = "allowed"
                    w.send(packet)

                root.after(0, update_packet_log_row, (
                    time_now, direction, protocol, src_ip, src_port, dst_ip, dst_port, size, status
                ), tag)
    except Exception as e:
        print(f"[Firewall Error] {e}")

def start_sniffing():
    global firewall_running, sniff_thread
    if not firewall_running:
        firewall_running = True
        sniff_thread = threading.Thread(target=sniff_packets, daemon=True)
        sniff_thread.start()
        status_label.config(text="Status: Running", fg="green")
        messagebox.showinfo("Firewall", "Firewall started!")

def stop_sniffing():
    global firewall_running
    if firewall_running:
        firewall_running = False
        status_label.config(text="Status: Stopped", fg="red")
        messagebox.showinfo("Firewall", "Firewall stopped.")

def add_ip():
    ip = simpledialog.askstring("Block IP", "Enter IP to block:")
    if ip and ip not in block_ips:
        block_ips.append(ip)
        save_rules({"block_ips": block_ips, "block_ports": block_ports})
        update_lists()

def add_port():
    try:
        port = int(simpledialog.askstring("Block Port", "Enter Port to block:"))
        if port not in block_ports:
            block_ports.append(port)
            save_rules({"block_ips": block_ips, "block_ports": block_ports})
            update_lists()
    except:
        pass

def remove_ip():
    selected = listbox_ips.curselection()
    if selected:
        block_ips.pop(selected[0])
        save_rules({"block_ips": block_ips, "block_ports": block_ports})
        update_lists()

def remove_port():
    selected = listbox_ports.curselection()
    if selected:
        block_ports.pop(selected[0])
        save_rules({"block_ips": block_ips, "block_ports": block_ports})
        update_lists()

# ---------------------- Button Events ----------------------
btn_start.config(command=start_sniffing)
btn_stop.config(command=stop_sniffing)
btn_add_ip.config(command=add_ip)
btn_add_port.config(command=add_port)
btn_remove_ip.config(command=remove_ip)
btn_remove_port.config(command=remove_port)

packet_log.tag_configure("blocked", background="red")
packet_log.tag_configure("allowed", background="lightgreen")

root.mainloop()
