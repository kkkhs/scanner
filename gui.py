import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from scanner import PortScanner
import threading
import queue
import ipaddress

class PortScannerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("端口扫描工具")
        self.root.geometry("800x600")

        self.scanner = PortScanner()
        self.scanning_label = None
        self.setup_gui()
        self.update_results()

    def setup_gui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # IP 输入区域
        ttk.Label(main_frame, text="起始 IP:").grid(row=0, column=0, padx=5, pady=5)
        self.start_ip = ttk.Entry(main_frame, width=20)
        self.start_ip.grid(row=0, column=1, padx=5, pady=5)
        self.start_ip.insert(0, "192.168.1.1")

        ttk.Label(main_frame, text="结束 IP:").grid(row=0, column=2, padx=5, pady=5)
        self.end_ip = ttk.Entry(main_frame, width=20)
        self.end_ip.grid(row=0, column=3, padx=5, pady=5)
        self.end_ip.insert(0, "192.168.1.255")

        # 端口输入区域
        ttk.Label(main_frame, text="端口范围:").grid(row=1, column=0, padx=5, pady=5)
        self.ports = ttk.Entry(main_frame, width=40)
        self.ports.grid(row=1, column=1, columnspan=2, padx=5, pady=5)
        self.ports.insert(0, "21,22,23,25,53,80,161,443,3389")

        # 协议选择
        self.protocol = tk.StringVar(value="TCP")
        ttk.Radiobutton(main_frame, text="TCP", variable=self.protocol, 
                       value="TCP").grid(row=1, column=3, padx=5, pady=5)
        ttk.Radiobutton(main_frame, text="UDP", variable=self.protocol, 
                       value="UDP").grid(row=1, column=4, padx=5, pady=5)

        # 进度条区域
        self.progress_frame = ttk.Frame(main_frame)
        self.progress_frame.grid(row=2, column=0, columnspan=5, pady=5)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self.progress_frame, 
            length=400, 
            mode='determinate',
            variable=self.progress_var
        )
        self.progress_bar.pack(side=tk.LEFT, padx=5)

        self.progress_label = ttk.Label(self.progress_frame, text="0%")
        self.progress_label.pack(side=tk.LEFT, padx=5)

        # 添加正在扫描的标签
        self.scanning_label = ttk.Label(self.progress_frame, text="")
        self.scanning_label.pack(side=tk.LEFT, padx=5)

        # 按钮区域
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=5, pady=10)

        self.start_button = ttk.Button(button_frame, text="开始扫描", 
                                     command=self.start_scan)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(button_frame, text="停止扫描", 
                                    command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # 结果显示区域
        self.result_text = scrolledtext.ScrolledText(main_frame, height=20, width=80)
        self.result_text.grid(row=4, column=0, columnspan=5, pady=10)

    def validate_inputs(self):
        try:
            start = ipaddress.IPv4Address(self.start_ip.get())
            end = ipaddress.IPv4Address(self.end_ip.get())
            if start > end:
                raise ValueError("起始 IP 必须小于或等于结束 IP")

            ports = []
            for p in self.ports.get().split(','):
                if '-' in p:
                    start_port, end_port = map(int, p.split('-'))
                    ports.extend(range(start_port, end_port + 1))
                else:
                    ports.append(int(p))

            return True, ports
        except Exception as e:
            messagebox.showerror("输入错误", str(e))
            return False, None

    def update_progress(self, percentage):
        self.progress_var.set(percentage)
        self.progress_label.config(text=f"{percentage:.1f}%")

    def reset_progress(self):
        self.progress_var.set(0)
        self.progress_label.config(text="0%")

    def start_scan(self):
        valid, ports = self.validate_inputs()
        if not valid:
            return

        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        # 设置文本标签
        self.result_text.tag_configure("open", foreground="green")
        self.result_text.tag_configure("closed", foreground="red")
        self.reset_progress()
        self.scanning_label.config(text="准备开始扫描...")

        scan_thread = threading.Thread(
            target=self.scanner.scan_range,
            args=(
                self.start_ip.get(),
                self.end_ip.get(),
                ports,
                self.protocol.get()
            )
        )
        scan_thread.daemon = True
        scan_thread.start()

    def stop_scan(self):
        self.scanner.stop_scanning()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def update_results(self):
        try:
            while True:
                result = self.scanner.result_queue.get_nowait()
                if result.startswith("PROGRESS:"):
                    percentage = float(result.split(":")[1])
                    if percentage >= 100:  # 当进度达到100%时停止更新进度条
                        self.update_progress(100)
                        self.scanning_label.config(text="扫描完成")
                        self.start_button.config(state=tk.NORMAL)
                        self.stop_button.config(state=tk.DISABLED)
                    else:
                        self.update_progress(percentage)
                elif result.startswith("SCANNING:"):
                    # 更新正在扫描的IP和端口信息
                    current = result.split(":")[1]
                    self.scanning_label.config(text=f"正在扫描: {current}")
                elif result == "<<<扫描完成>>>":
                    self.update_progress(100)
                    self.scanning_label.config(text="扫描完成")
                    self.start_button.config(state=tk.NORMAL)
                    self.stop_button.config(state=tk.DISABLED)
                    self.result_text.insert(tk.END, "\n=== 扫描完成！===\n")
                elif result.startswith("[+]"):
                    # 开放的端口
                    self.result_text.insert(tk.END, result + '\n', "open")
                else:
                    # 未开放的端口
                    self.result_text.insert(tk.END, result + '\n', "closed")
                self.result_text.see(tk.END)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.update_results)

    def run(self):
        self.root.mainloop()