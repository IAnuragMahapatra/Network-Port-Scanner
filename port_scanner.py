import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import queue
import ipaddress
from concurrent.futures import ThreadPoolExecutor


class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Port Scanner")
        self.root.geometry("700x600")
        self.root.configure(bg="#f0f0f0")

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TLabelframe", background="#f0f0f0")
        self.style.configure("TLabelframe.Label", font=("Helvetica", 10, "bold"))
        self.style.configure("TButton", padding=5, font=("Helvetica", 9))
        self.style.configure("Scan.TButton", background="#4CAF50", foreground="white")
        self.style.configure("Abort.TButton", background="#f44336", foreground="white")
        self.style.configure(
            "TProgressbar",
            thickness=15,
            troughcolor="#E0E0E0",
            background="#2196F3",
            bordercolor="#FFFFFF",
            lightcolor="#2196F3",
            darkcolor="#2196F3",
        )

        self.scan_queue = queue.Queue()
        self.scanning = False
        self.create_widgets()

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill="both", expand=True)

        title_label = ttk.Label(
            main_frame,
            text="Network Port Scanner",
            font=("Helvetica", 16, "bold"),
            foreground="#2196F3",
        )
        title_label.pack(pady=(0, 20))

        input_frame = ttk.LabelFrame(main_frame, text="Scan Settings", padding="15")
        input_frame.pack(fill="x", padx=5, pady=(0, 15))

        ip_frame = ttk.Frame(input_frame)
        ip_frame.pack(fill="x", pady=5)

        ttk.Label(ip_frame, text="Target IP:", font=("Helvetica", 10)).pack(side="left")

        self.ip_entry = ttk.Entry(ip_frame, width=25, font=("Helvetica", 10))
        self.ip_entry.pack(side="left", padx=(10, 0))
        self.ip_entry.insert(0, "127.0.0.1")

        port_frame = ttk.Frame(input_frame)
        port_frame.pack(fill="x", pady=10)

        ttk.Label(port_frame, text="Port Range:", font=("Helvetica", 10)).pack(
            side="left"
        )

        port_input_frame = ttk.Frame(port_frame)
        port_input_frame.pack(side="left", padx=(10, 0))

        self.start_port = ttk.Entry(port_input_frame, width=7, font=("Helvetica", 10))
        self.start_port.pack(side="left")
        self.start_port.insert(0, "1")

        ttk.Label(port_input_frame, text="→", font=("Helvetica", 10, "bold")).pack(
            side="left", padx=5
        )

        self.end_port = ttk.Entry(port_input_frame, width=7, font=("Helvetica", 10))
        self.end_port.pack(side="left")
        self.end_port.insert(0, "1024")

        button_frame = ttk.Frame(input_frame)
        button_frame.pack(pady=(10, 0))

        self.scan_button = ttk.Button(
            button_frame,
            text="Start Scan",
            command=self.start_scan,
            style="Scan.TButton",
            width=15,
        )
        self.scan_button.pack(side="left", padx=5)

        self.abort_button = ttk.Button(
            button_frame,
            text="Abort",
            command=self.abort_scan,
            style="Abort.TButton",
            state="disabled",
            width=15,
        )
        self.abort_button.pack(side="left", padx=5)

        result_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding="15")
        result_frame.pack(fill="both", expand=True, pady=(0, 15))

        self.result_text = scrolledtext.ScrolledText(
            result_frame,
            height=15,
            font=("Consolas", 10),
            background="#ffffff",
            borderwidth=1,
            relief="solid",
        )
        self.result_text.pack(fill="both", expand=True)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            main_frame,
            variable=self.progress_var,
            maximum=100,
            mode="determinate",
            style="TProgressbar",
            length=300,
        )
        self.progress_bar.pack(fill="x", padx=20, pady=(0, 10))

        self.status_label = ttk.Label(
            main_frame,
            text="Ready to scan",
            font=("Helvetica", 9),
            foreground="#666666",
        )
        self.status_label.pack()

    def validate_inputs(self):
        try:
            ip = ipaddress.ip_address(self.ip_entry.get())
            start_port = int(self.start_port.get())
            end_port = int(self.end_port.get())

            if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535):
                raise ValueError("Ports must be between 0 and 65535")
            if start_port > end_port:
                raise ValueError("Start port must be less than end port")

            return True
        except ValueError as e:
            messagebox.showerror("Input Error", str(e))
            return False

    def scan_port(self, ip, port):
        if not self.scanning:
            return
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                if result == 0:
                    self.scan_queue.put(f"Port {port}: Open")
        except:
            pass

    def update_results(self):
        while True:
            try:
                message = self.scan_queue.get_nowait()
                self.result_text.insert(tk.END, message + "\n")
                self.result_text.see(tk.END)
            except queue.Empty:
                break

        if self.scanning:
            self.root.after(100, self.update_results)

    def abort_scan(self):
        self.scanning = False
        self.scan_queue.put("\nScan aborted!")
        self.scan_button.config(state="normal")
        self.abort_button.config(state="disabled")

    def start_scan(self):
        if not self.validate_inputs():
            return

        self.scan_button.config(state="disabled")
        self.abort_button.config(state="normal")
        self.result_text.delete(1.0, tk.END)
        self.scanning = True
        self.progress_var.set(0)

        ip = self.ip_entry.get()
        start_port = int(self.start_port.get())
        end_port = int(self.end_port.get())

        self.result_text.insert(
            tk.END, f"Starting scan of {ip} from port {start_port} to {end_port}\n"
        )

        def scan_thread():
            ports = range(start_port, end_port + 1)
            total_ports = len(ports)
            completed_ports = 0

            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = [executor.submit(self.scan_port, ip, port) for port in ports]

                for future in futures:
                    if not self.scanning:
                        executor.shutdown(wait=False)
                        break
                    future.result()
                    completed_ports += 1
                    progress = (completed_ports / total_ports) * 100
                    self.progress_var.set(progress)

            if self.scanning:
                self.scanning = False
                self.scan_queue.put("\nScan completed!")
                self.scan_button.config(state="normal")
                self.abort_button.config(state="disabled")
                self.progress_var.set(100)

        self.update_results()
        threading.Thread(target=scan_thread, daemon=True).start()


if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerGUI(root)
    root.mainloop()
