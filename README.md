# Personal Firewall 🚀

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![GitHub Repo stars](https://img.shields.io/github/stars/BruhhMoment123/Personal-Firewall?style=social)

A **simple yet powerful Windows-based mini firewall** built using **Python**, **Tkinter**, and **WinDivert**. It features a real-time GUI for monitoring, filtering, and blocking IP and port-based network traffic.

---

## 🔧 Features

- 🔐 Block traffic from/to specific IPs or ports
- 📊 Real-time packet logging (direction, protocol, IPs, ports)
- 🖥️ Graphical user interface using Tkinter
- 💾 Persistent rules saved in `rules.json`
- 🧱 Backend powered by WinDivert via `pydivert`
- 🛠️ Create `.exe` using PyInstaller

---

## 📁 Project Structure

```
├── build/            # Auto-generated exe build files
├── dist/             # Final executable files
├── drivers/          # WinDivert drivers (WinDivert.dll, .sys)
├── logs/             # Packet logs (optional)
├── src/              # Source code (e.g., firewall.py)
├── rules.json        # Stores user-defined firewall rules
├── firewall.spec     # PyInstaller build spec
└── README.md         # You're here!
```

---

## ▶️ How to Run

```bash
pip install pydivert
python src/firewall.py
```

> Requires Administrator privileges

---

## 🛠 How to Build the EXE

1. Install PyInstaller:

```bash
pip install pyinstaller
```

2. Run:

```bash
pyinstaller firewall.spec
```

The `.exe` will be available in the `dist/` folder.

---

## 📄 License

MIT License © 2025 BruhhMoment123
