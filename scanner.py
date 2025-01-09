import socket
import threading
import random
import time
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import ipaddress

class PortScanner:
    def __init__(self):
        self.stop_scan = False
        self.result_queue = Queue()
        self.setup_logging()
        self.is_scanning = False
        self.total_tasks = 0
        self.completed_tasks = 0

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def tcp_scan(self, ip, port, timeout=1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                self.result_queue.put(f"SCANNING:{ip}:{port}")
                result = sock.connect_ex((ip, port))
                service = self.get_service_name(port) if result == 0 else "unknown"

                if result == 0:
                    self.result_queue.put(f"[+] {ip}:{port} TCP OPEN ({service})")
                    self.logger.info(f"Found open TCP port {port} on {ip}")
                else:
                    # 更明确地标识关闭的端口
                    status = "FILTERED" if result == 111 else "CLOSED"  # 111 通表示连接被拒绝
                    self.result_queue.put(f"[-] {ip}:{port} TCP {status}")
        except socket.timeout:
            self.result_queue.put(f"[-] {ip}:{port} TCP FILTERED")
        except Exception as e:
            self.result_queue.put(f"[-] {ip}:{port} TCP ERROR ({str(e)})")

    def udp_scan(self, ip, port, timeout=1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                self.result_queue.put(f"SCANNING:{ip}:{port}")

                # 发送一个空的 UDP 包
                sock.sendto(b'', (ip, port))

                try:
                    # 尝试接收响应
                    data, _ = sock.recvfrom(1024)
                    service = self.get_service_name(port)
                    self.result_queue.put(f"[+] {ip}:{port} UDP OPEN ({service})")
                    self.logger.info(f"Found open UDP port {port} on {ip}")
                except socket.timeout:
                    # UDP 超时可能意味着端口被过滤
                    self.result_queue.put(f"[-] {ip}:{port} UDP FILTERED")
                except socket.error as e:
                    if e.errno == 10054:  # 连接重置
                        self.result_queue.put(f"[-] {ip}:{port} UDP CLOSED")
                    else:
                        self.result_queue.put(f"[-] {ip}:{port} UDP ERROR ({str(e)})")
        except Exception as e:
            self.result_queue.put(f"[-] {ip}:{port} UDP ERROR ({str(e)})")

    def get_service_name(self, port):
        try:
            return socket.getservbyport(port)
        except:
            return "unknown"

    def scan_host(self, ip, ports, protocol='TCP'):
        if self.stop_scan:
            return

        results = []
        scan_func = self.tcp_scan if protocol == 'TCP' else self.udp_scan
        random_ports = list(ports)
        random.shuffle(random_ports)

        for port in random_ports:
            if self.stop_scan:
                break
            scan_func(ip, port)
            self.completed_tasks += 1
            progress = (self.completed_tasks / self.total_tasks) * 100
            self.result_queue.put(f"PROGRESS:{progress}")
            time.sleep(random.uniform(0.01, 0.1))

    def scan_range(self, start_ip, end_ip, ports, protocol='TCP', max_threads=20):
        self.stop_scan = False
        self.is_scanning = True
        self.completed_tasks = 0

        try:
            start = ipaddress.IPv4Address(start_ip)
            end = ipaddress.IPv4Address(end_ip)

            ip_list = [str(ipaddress.IPv4Address(ip)) 
                      for ip in range(int(start), int(end) + 1)]

            # 计算总任务数：IP数量 × 端口数量
            self.total_tasks = len(ip_list) * len(ports)

            random.shuffle(ip_list)

            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for ip in ip_list:
                    if self.stop_scan:
                        break
                    future = executor.submit(self.scan_host, ip, ports, protocol)
                    futures.append(future)

                # 等待所有任务完成
                for future in as_completed(futures):
                    if self.stop_scan:
                        break
                    try:
                        future.result()  # 获取结果，确保异常被捕获
                    except Exception as e:
                        self.logger.error(f"Error in scan task: {e}")

        except Exception as e:
            self.logger.error(f"Error in scan_range: {e}")
        finally:
            self.is_scanning = False
            # 确保进度到达100%
            if not self.stop_scan:
                self.result_queue.put("PROGRESS:100.0")
            self.result_queue.put("<<<扫描完成>>>")

    def stop_scanning(self):
        self.stop_scan = True