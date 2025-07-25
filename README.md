# 🔥 Mini Firewall with GUI (Python + WinDivert)

This is a simple Python-based GUI firewall for Windows using WinDivert. It allows you to block specific IP addresses and ports with real-time packet logging and now includes **scrollable packet logs** for easier monitoring.

---

## 📁 Folder Structure

```
firewall/
├── build/                  # PyInstaller build output
├── dist/                   # Final .exe file
├── drivers/                # WinDivert DLLs (e.g., WinDivert64.dll)
├── src/                    # Main application source code
│   └── firewall.py         # Main GUI + Firewall logic
├── rules.json              # Stores blocked IPs and ports
├── client.py               # Sample client for testing (e.g., socket connection)
├── testserver.py           # Sample server for testing
├── testfirewall_bypass.py  # Script for bypass attempts (for testing)
├── firewall.spec           # PyInstaller spec file
├── README.md
└── LICENSE.txt             # MIT License
```

---

## 🚀 Features

- ✅ Block any IP address or port
- ✅ Start/stop firewall easily from the GUI
- ✅ Scrollable log window for packet events
- ✅ Real-time packet log: direction, protocol, IPs, ports, size, status
- ✅ Persistent rules via `rules.json`

---

## 📦 Requirements

- **Windows**
- **Python 3.11**
- `pydivert`
- `tkinter`

Install dependencies:
```bash
pip install pydivert
```

Place `WinDivert64.dll` in the same folder or `drivers/` directory.

---

## 🛠️ How to Run

```bash
cd src
python firewall.py
```

---

## 🧪 Testing

You can use the included `client.py` and `testserver.py` to simulate connections and see blocking in action.

---

## 🧾 Notes

- Rules (IPs and ports) are saved to `rules.json`
- Logs are scrollable and color-coded:
  - 🟩 Allowed → green
  - 🟥 Blocked → red
- Packet capture is done using WinDivert, so **admin privileges are required** to run the app or `.exe`.

---

## 🔒 License

This project is licensed under the MIT License.
