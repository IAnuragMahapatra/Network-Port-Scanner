# 🔍 Network Port Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3-deepgreen.svg)](https://www.python.org/downloads/)

An efficient and user-friendly network port scanner built with Python's Tkinter, socket and threading libraries. This tool helps identify open ports on a target IP address, making it ideal for network diagnostics and security assessments. Compatible with Windows, macOS and Linux.

> [!IMPORTANT]
> Always ensure you have explicit permission before scanning a network.                  
> Unauthorized port scanning may violate laws and regulations and could result in legal consequences.


## ✨ Features

- **Targeted Scanning**: Specify the target IP and a custom port range to identify open ports efficiently.
- **Concurrent Execution**: Utilizes a ThreadPoolExecutor to scan multiple ports simultaneously, significantly speeding up the process.
- **Real-Time Updates**: Displays scan results in a scrollable text area as open ports are discovered.
- **Progress Monitoring**: Features a progress bar to visually track the scanning progress.
- **Abort Capability**: Stop the scan at any time with a single click if needed.
- **Input Validation & Error Handling**: Ensures valid IP addresses and port ranges (0–65535) with clear error messages for incorrect inputs.

## 🖼️ Screenshots


<div align="center">
  <img src="https://github.com/IAnuragMahapatra/Network-Port-Scanner/blob/main/Screenshots/main_interface.png" width="45%" style="display: inline-block;">
  <img src="https://github.com/IAnuragMahapatra/Network-Port-Scanner/blob/main/Screenshots/scanning_progress.png" width="45%" style="display: inline-block;">
</div>

## ⚙️ Requirements

To run this application, you need:
- **Python 3** (Download from [python.org](https://www.python.org/downloads/))
- Built-in Python libraries:
  - `Tkinter` (GUI framework, included with Python; on Linux, install with `sudo apt-get install python3-tk`)
  - `socket` (for network operations)
  - `threading` (for concurrency)
  - `queue` (for thread-safe communication)
  - `ipaddress` (for IP validation)
  - `concurrent.futures` (for parallel execution)

**No external packages are required.**
**The tool works on Windows, macOS and Linux.**

## 🚀 Installation

1. **Clone the Repository (Recommended):**
   ```bash
   git clone https://github.com/IAnuragMahapatra/Network-Port-Scanner.git
   cd Network-Port-Scanner
   ```
   or
   **Download as ZIP:**
   - Visit [github.com/IAnuragMahapatra/Network-Port-Scanner](https://github.com/IAnuragMahapatra/Network-Port-Scanner)
   - Click **Code > Download ZIP**, extract, and navigate to the folder.

3. **Run the Application:**
   ```bash
   python port_scanner.py

## 📝 Usage

1. **Launch the Application:**
   Run `python port_scanner.py` to open the GUI.

2. **Enter Parameters:**
   - **Target IP:** Input a valid IP address (e.g., `192.168.1.1` or `127.0.0.1` for localhost).
   - **Port Range:** Specify the start (e.g., `1`) and end (e.g., `1024`) ports.

3. **Start Scanning:**
   Click **"Start Scan"** to begin. Open ports will appear in the results area in real-time.

4. **Monitor Progress:**
   Watch the progress bar to see how far the scan has progressed.

5. **Abort if Needed:**
   Click **"Abort"** to stop the scan immediately.

6. **Review Results:**
   Check the scrollable text area for a list of open ports.

### Examples
- **Scan localhost ports 1–100:**
  - IP: `127.0.0.1`
  - Start Port: `1`
  - End Port: `100`
- **Scan a router ports 20–80:**
  - IP: `192.168.1.1`
  - Start Port: `20`
  - End Port: `80`

> **Tip:** For large port ranges (e.g., 1–65535), scans may take longer depending on network speed and system resources.

## 🏗️ Code Structure

- **GUI Components:** Built with Tkinter (Frames, Labels, Entry fields, Buttons, ScrolledText and Progressbar) for an intuitive interface.
- **Input Validation:** Ensures the target IP and port range (0–65535) are valid before scanning begins.
- **Port Scanning Logic:** Uses the `socket` module to test each port, detecting open ones via successful connections.
- **Threading & Concurrency:** Employs a ThreadPoolExecutor for parallel scanning, with progress updates via a `queue`.
- **Abort Functionality:** Halts further port checks instantly when the user aborts the scan.

## 🤝 Contributing

Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a new branch for your feature or fix.
3. Submit a pull request with a clear description of your changes.

For bugs or feature requests, please open an issue on the [GitHub repository](https://github.com/IAnuragMahapatra/Network-Port-Scanner/issues).

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 📧 Contact

📌 **Author:** Anurag Mahapatra  
📩 **Email:** [anurag2005om@gmail.com](mailto:anurag2005om@gmail.com)

---

🎉 Start exploring networks with the **Network Port Scanner** today! 🚀
