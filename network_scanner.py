import socket
import threading
import tkinter as tk
from tkinter import ttk

class NetworkScanner:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Network Security Scanner")
        self.root.geometry("700x600")
        
        # переменные
        self.devices = []
        self.common_ports = [21, 22, 23, 80, 443, 3389, 53, 110, 143, 993]
        self.scanning = False
        self.threads = []
        
        self.setup_ui()
    
    def setup_ui(self):
        # Заголовок
        label = tk.Label(self.root, text="🔍 Network Security Scanner",
                        font=("Arial", 16, "bold"))
        label.pack(pady=10)

        # Фрейм для настроек
        settings_frame = tk.Frame(self.root)
        settings_frame.pack(pady=10, fill="x", padx=20)

        # Поле ввода IP 
        tk.Label(settings_frame, text="IP диапазон:", font=("Arial", 10)).grid(row=0, column=0, sticky="w")
        self.ip_entry = tk.Entry(settings_frame, width=20, font=("Arial", 10))
        self.ip_entry.grid(row=0, column=1, padx=5)
        self.ip_entry.insert(0, "192.168.1.1-10")

        # Поле для портов
        tk.Label(settings_frame, text="Порты:", font=("Arial", 10)).grid(row=1, column=0, sticky="w", pady=5)
        self.ports_entry = tk.Entry(settings_frame, width=20, font=("Arial", 10))
        self.ports_entry.grid(row=1, column=1, padx=5)
        self.ports_entry.insert(0, "21,22,23,80,443,3389")

        # кнопка скана
        self.scan_btn = tk.Button(settings_frame, text="🚀 Начать сканирование",
                                command=self.scan_network_threaded,
                                bg="#4CAF50", fg="white", font=("Arial", 10, "bold"))
        self.scan_btn.grid(row=0, column=2, rowspan=2, padx=10)

        # прогресс-бар
        self.progress = ttk.Progressbar(self.root, mode='indeterminate')
        self.progress.pack(fill="x", padx=20, pady=5)

        # текстовый вывод 
        output_frame = tk.Frame(self.root)
        output_frame.pack(fill="both", expand=True, padx=20, pady=10)

        tk.Label(output_frame, text="Результаты сканирования:", font=("Arial", 11, "bold")).pack(anchor="w")
        
        self.result_text = tk.Text(output_frame, height=20, width=80, font=("Consolas", 9))
        self.result_text.pack(side="left", fill="both", expand=True)

        scrollbar = tk.Scrollbar(output_frame, command=self.result_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.result_text.config(yscrollcommand=scrollbar.set)

        # Статус бар
        self.status_var = tk.StringVar(value="Готов к сканированию")
        status_bar = tk.Label(self.root, textvariable=self.status_var, relief="sunken", anchor="w")
        status_bar.pack(fill="x", side="bottom")

    def check_port(self, ip, port):
        """Проверяет открыт ли порт на указанном IP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    def scan_single_ip(self, ip):
        """Сканирует один IP адрес (выполняется в потоке)"""
        open_ports = []
        
        # Обновляем статус
        self.root.after(0, lambda: self.status_var.set(f"Сканирую {ip}..."))
        
        # Проверяем каждый порт
        for port in self.common_ports:
            if not self.scanning:  # Если сканирование прервано
                return
                
            if self.check_port(ip, port):
                open_ports.append(port)
                # Обновляем интерфейс в основном потоке
                self.root.after(0, lambda p=port, i=ip: 
                              self.result_text.insert(tk.END, f"   ✅ {i}:{p} открыт\n"))
                self.root.after(0, lambda: self.result_text.see(tk.END))
        
        # Если нашли открытые порты
        if open_ports:
            self.devices.append({'ip': ip, 'ports': open_ports})
            self.root.after(0, lambda i=ip, op=open_ports: 
                           self.result_text.insert(tk.END, f"🎯 Устройство {i} найдено! Порты: {op}\n\n"))
        else:
            self.root.after(0, lambda i=ip: 
                           self.result_text.insert(tk.END, f"   ❌ {i} - активных портов не найдено\n\n"))

    def scan_network_threaded(self):
        """Запускает сканирование в отдельном потоке"""
        if self.scanning:
            return
            
        # Очищаем результаты
        self.result_text.delete(1.0, tk.END)
        self.devices = []
        self.threads = []
        
        # Парсим порты из поля ввода
        try:
            ports_text = self.ports_entry.get()
            self.common_ports = [int(port.strip()) for port in ports_text.split(",")]
        except:
            self.common_ports = [21, 22, 23, 80, 443, 3389, 53, 110, 143, 993]
        
        # Запускаем прогресс-бар
        self.progress.start()
        self.scanning = True
        self.scan_btn.config(state="disabled", text="⏳ Сканирование...")
        
        self.result_text.insert(tk.END, "🔍 Начинаю сканирование...\n")
        self.result_text.insert(tk.END, f"📡 Порты для сканирования: {self.common_ports}\n\n")

        try:
            ip_range = self.ip_entry.get()
            
            if '-' in ip_range:
                base_ip = ip_range.split('-')[0].rsplit('.', 1)[0] + "."
                start_ip = int(ip_range.split('-')[0].split('.')[-1])
                end_ip = int(ip_range.split('-')[1])
                
                # Создаем отдельный поток для каждого IP
                for i in range(start_ip, end_ip + 1):
                    if not self.scanning:
                        break
                    ip = base_ip + str(i)
                    thread = threading.Thread(target=self.scan_single_ip, args=(ip,))
                    thread.daemon = True
                    self.threads.append(thread)
                    thread.start()
                
                # Запускаем проверку завершения
                self.root.after(100, self.check_threads_completion)
                
        except Exception as e:
            self.finish_scanning(f"❌ Ошибка ввода: {e}\n")

    def check_threads_completion(self):
        """Проверяет завершились ли все потоки"""
        if self.scanning:
            # Считаем активные потоки
            alive_threads = sum(1 for thread in self.threads if thread.is_alive())
            
            if alive_threads == 0:
                # Все потоки завершились
                self.finish_scanning(f"\n🎉 Сканирование завершено! Найдено устройств: {len(self.devices)}\n")
            else:
                # Обновляем статус
                self.status_var.set(f"Сканирование... Осталось: {alive_threads} IP")
                # Проверяем снова через 100ms
                self.root.after(100, self.check_threads_completion)

    def finish_scanning(self, message):
        """Завершает сканирование и показывает результаты"""
        self.scanning = False
        self.progress.stop()
        self.scan_btn.config(state="normal", text="🚀 Начать сканирование")
        self.status_var.set("Готов к сканированию")
        self.result_text.insert(tk.END, message)
        self.result_text.see(tk.END)

    def run(self):
        self.root.mainloop()

# Запуск программы
if __name__ == "__main__":
    scanner = NetworkScanner()
    scanner.run()