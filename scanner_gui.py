#!/usr/bin/env python3
"""
Network Security Scanner v6.5 — GUI
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import ipaddress
from datetime import datetime
import os
import subprocess
import queue
import random
import re
import sys
import math

# Импортируем движок v6 с алиасом
from scanner_engine import ScannerEngineV6 as ScannerEngine
from scanner_engine import generate_html_report, generate_json_report, ScannerEvent, ScanPhase, ScanMode

# =======================================================
#  GUI Класс
# =======================================================

class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 Network Security Scanner v6.5")
        self.root.geometry("1050x850")
        self.root.minsize(800, 600)
        
        # Переменные
        self.target_var = tk.StringVar()
        self.timeout_var = tk.DoubleVar(value=3.0)
        self.workers_var = tk.IntVar(value=5)
        self.format_var = tk.StringVar(value="all")
        self.mode_var = tk.StringVar(value="universal")
        self.model_var = tk.StringVar()
        self.firmware_var = tk.StringVar()
        self.service_map_var = tk.StringVar()
        self.ports_var = tk.StringVar()
        self.hosts_var = tk.IntVar(value=256)
        self.udp_var = tk.BooleanVar(value=False)
        self.cve_var = tk.BooleanVar(value=False)
        self.is_scanning = False
        self.scan_thread = None
        self.cancel_event = threading.Event()
        self.event_queue = queue.Queue()
        self.current_scan_id = None
        
        # Стили
        self._setup_styles()
        
        # Интерфейс
        self._create_widgets()
        
        # Таймер для обработки событий
        self.root.after(100, self._process_events)
        
    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TLabel', font=('Segoe UI', 10))
        style.configure('TButton', font=('Segoe UI', 10, 'bold'))
        style.configure('Header.TLabel', font=('Segoe UI', 14, 'bold'))
        
    def _create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Заголовок
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 15))
        ttk.Label(header_frame, text="🔒 Network Security Scanner v6.5", style='Header.TLabel').pack(side=tk.LEFT)
        ttk.Label(header_frame, text="Web · Network services · Configuration audit", font=('Segoe UI', 9), foreground='gray').pack(side=tk.RIGHT)
        
        # Панель ввода
        input_frame = ttk.LabelFrame(main_frame, text="Scan Configuration", padding="15")
        input_frame.pack(fill=tk.X, pady=(0, 15))
        
        # 1 строка: Target
        row1 = ttk.Frame(input_frame)
        row1.pack(fill=tk.X, pady=5)
        ttk.Label(row1, text="Target:", width=15).pack(side=tk.LEFT)
        target_entry = ttk.Entry(row1, textvariable=self.target_var, font=('Segoe UI', 11))
        target_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        ttk.Label(row1, text="IP / hostname / CIDR / URL", font=('Segoe UI', 9), foreground='gray').pack(side=tk.RIGHT)
        
        # 2 строка: Timeout + Workers + Mode
        row2 = ttk.Frame(input_frame)
        row2.pack(fill=tk.X, pady=5)
        
        ttk.Label(row2, text="Timeout (s):", width=15).pack(side=tk.LEFT)
        ttk.Spinbox(row2, from_=0.5, to=10.0, increment=0.5, textvariable=self.timeout_var, width=8).pack(side=tk.LEFT, padx=(0, 30))
        
        ttk.Label(row2, text="Workers:", width=10).pack(side=tk.LEFT)
        ttk.Spinbox(row2, from_=5, to=100, increment=5, textvariable=self.workers_var, width=8).pack(side=tk.LEFT, padx=(0, 30))
        
        ttk.Label(row2, text="Mode:", width=10).pack(side=tk.LEFT)
        mode_combo = ttk.Combobox(row2, textvariable=self.mode_var, values=["universal", "keenetic", "safe", "standard", "extended", "aggressive"], width=10, state="readonly")
        mode_combo.pack(side=tk.LEFT)
        
        # 3 строка: Format
        row3 = ttk.Frame(input_frame)
        row3.pack(fill=tk.X, pady=5)
        
        ttk.Label(row3, text="Report format:", width=15).pack(side=tk.LEFT)
        ttk.Combobox(row3, textvariable=self.format_var, values=["html", "json", "all"], width=10, state="readonly").pack(side=tk.LEFT)
        
        advanced = ttk.Frame(input_frame)
        advanced.pack(fill=tk.X,pady=5)
        ttk.Label(advanced,text="TCP ports:",width=15).pack(side=tk.LEFT)
        ttk.Entry(advanced,textvariable=self.ports_var,width=30).pack(side=tk.LEFT)
        ttk.Label(advanced,text=" Empty = mode preset; e.g. 22,443,8000-8100").pack(side=tk.LEFT)
        options = ttk.Frame(input_frame)
        options.pack(fill=tk.X,pady=5)
        ttk.Label(options,text="Host limit:",width=15).pack(side=tk.LEFT)
        ttk.Spinbox(options,from_=1,to=4096,textvariable=self.hosts_var,width=7).pack(side=tk.LEFT)
        ttk.Checkbutton(options,text="UDP discovery",variable=self.udp_var).pack(side=tk.LEFT,padx=10)
        ttk.Checkbutton(options,text="Online CVE (NVD)",variable=self.cve_var).pack(side=tk.LEFT,padx=10)

        service_row = ttk.Frame(input_frame)
        service_row.pack(fill=tk.X,pady=5)
        ttk.Label(service_row,text="Protocol ports:",width=15).pack(side=tk.LEFT)
        ttk.Entry(service_row,textvariable=self.service_map_var,width=30).pack(side=tk.LEFT)
        ttk.Label(service_row,text="Optional: 1884=mqtt,33389=rdp",foreground='gray').pack(side=tk.LEFT,padx=8)
        identity = ttk.Frame(input_frame)
        def show_vendor_fields(event=None):
            if self.mode_var.get() == 'keenetic':
                identity.pack(fill=tk.X,pady=5)
            else:
                identity.pack_forget()
        mode_combo.bind('<<ComboboxSelected>>', show_vendor_fields)
        show_vendor_fields()
        ttk.Label(identity,text="Keenetic model:",width=15).pack(side=tk.LEFT)
        ttk.Entry(identity,textvariable=self.model_var,width=12).pack(side=tk.LEFT)
        ttk.Label(identity,text=" Firmware:").pack(side=tk.LEFT,padx=5)
        ttk.Entry(identity,textvariable=self.firmware_var,width=14).pack(side=tk.LEFT)
        ttk.Label(identity,text="Optional: from label/UI; one target only",foreground='gray').pack(side=tk.LEFT,padx=8)

        # Кнопки
        btn_frame = ttk.Frame(input_frame)
        btn_frame.pack(fill=tk.X, pady=(15, 0))
        
        self.scan_btn = ttk.Button(btn_frame, text="🚀 START SCAN", command=self.start_scan, width=20)
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_btn = ttk.Button(btn_frame, text="⏹ STOP", command=self.stop_scan, width=15, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)
        
        ttk.Button(btn_frame, text="📁 Open Reports Folder", command=self.open_folder, width=18).pack(side=tk.RIGHT, padx=(0, 10))
        ttk.Button(btn_frame, text="❌ Clear Log", command=self.clear_log, width=15).pack(side=tk.RIGHT)
        
        # Лог
        log_frame = ttk.LabelFrame(main_frame, text="Scan Output", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            font=('Consolas', 10),
            background='#1e1e2e',
            foreground='#cdd6f4',
            insertbackground='white',
            wrap=tk.WORD,
            height=20
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Теги
        self.log_text.tag_config('error', foreground='#f38ba8')
        self.log_text.tag_config('warning', foreground='#fab387')
        self.log_text.tag_config('success', foreground='#a6e3a1')
        self.log_text.tag_config('info', foreground='#89b4fa')
        self.log_text.tag_config('critical', foreground='#ff0000', font=('Consolas', 10, 'bold'))
        
        # Статус бар
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W, font=('Segoe UI', 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        target_entry.focus()
        self.root.bind('<Return>', lambda e: self.start_scan())
    
    def _log(self, message, tag='info'):
        self.event_queue.put(('log', message, tag))
    
    def _update_status(self, text):
        self.event_queue.put(('status', text))
    
    def _set_buttons(self, scanning):
        self.event_queue.put(('buttons', scanning))
    
    def _process_events(self):
        try:
            for _ in range(200):
                event = self.event_queue.get_nowait()
                if event[0] == 'log':
                    _, message, tag = event
                    self.log_text.insert(tk.END, message + "\n", tag)
                    self.log_text.see(tk.END)
                elif event[0] == 'status':
                    _, text = event
                    self.status_bar.config(text=text)
                elif event[0] == 'buttons':
                    _, scanning = event
                    self.is_scanning = scanning
                    self.scan_btn.config(state=tk.DISABLED if scanning else tk.NORMAL)
                    self.stop_btn.config(state=tk.NORMAL if scanning else tk.DISABLED)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self._process_events)
    
    def _event_callback(self, event: ScannerEvent):
        phase_emojis = {
            ScanPhase.INIT: "🚀", ScanPhase.RESOLVE: "🔍",
            ScanPhase.DISCOVERY: "📡", ScanPhase.FINGERPRINT: "🖐️",
            ScanPhase.OS_DETECT: "💻", ScanPhase.WEB: "🌐", ScanPhase.TLS: "🔐",
            ScanPhase.CVE: "📋", ScanPhase.CONFIG: "⚙️",
            ScanPhase.SCORING: "📊", ScanPhase.DONE: "✅"
        }
        emoji = phase_emojis.get(event.phase, "•")
        self._log(f"{emoji} {event.message}", 'info' if event.phase != ScanPhase.DONE else 'success')
        if event.progress > 0:
            self._update_status(f"{event.phase.value}: {event.progress*100:.0f}%")
    
    def clear_log(self):
        self.log_text.delete(1.0, tk.END)
        self._update_status("Log cleared")
    
    def open_folder(self):
        try:
            if os.name == 'nt':
                os.startfile(os.getcwd())
            else:
                subprocess.Popen(['open' if sys.platform == 'darwin' else 'xdg-open', os.getcwd()])
        except:
            messagebox.showinfo("Info", f"Reports saved in: {os.getcwd()}")
    
    def stop_scan(self):
        if self.is_scanning:
            self.cancel_event.set()
            self._log("⏹ Stopping scan...", 'warning')
            self._update_status("Stopping...")
    
    def start_scan(self):
        if self.is_scanning:
            messagebox.showwarning("Warning", "Scan is already running!")
            return
        
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter target!")
            return
        
        # Read and validate all Tk variables on the UI thread.
        try:
            config = {
                'target': target, 'timeout': self.timeout_var.get(),
                'workers': self.workers_var.get(), 'mode': self.mode_var.get(),
                'format': self.format_var.get(), 'ports': self.ports_var.get().strip(),
                'max_hosts': self.hosts_var.get(), 'udp': self.udp_var.get(),
                'cve_lookup': self.cve_var.get(), 'service_map':self.service_map_var.get().strip(),
                'device_model':self.model_var.get().strip() if self.mode_var.get()=='keenetic' else '',
                'firmware':self.firmware_var.get().strip() if self.mode_var.get()=='keenetic' else ''
            }
            if not math.isfinite(config['timeout']) or not 0.1 <= config['timeout'] <= 30:
                raise ValueError('Timeout must be 0.1–30 seconds')
            if not 1 <= config['workers'] <= 100 or not 1 <= config['max_hosts'] <= 4096:
                raise ValueError('Workers: 1–100; hosts: 1–4096')
            if config['ports']:
                ScannerEngine.parse_ports(config['ports'])
        except (ValueError,tk.TclError) as exc:
            messagebox.showerror('Invalid configuration',str(exc))
            return

        self.clear_log()
        self.cancel_event.clear()
        self.current_scan_id = random.randint(1000, 9999)
        self.is_scanning = True  # Close double-start race before the worker starts.
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self._update_status(f"Scanning {target}...")
        self._log("="*60, 'info')
        self._log(f"🔍 Starting scan: {target}", 'info')
        self._log(f"   Mode: {config['mode']}, Timeout: {config['timeout']}s, Workers: {config['workers']}", 'info')
        self._log("="*60, 'info')
        
        self.scan_thread = threading.Thread(
            target=self._run_scan,
            args=(config,),
            daemon=True
        )
        self.scan_thread.start()
    
    def _run_scan(self, config):
        try:
            # Конвертируем режим
            mode_map = {
                'safe': ScanMode.SAFE,
                'standard': ScanMode.STANDARD,
                'aggressive': ScanMode.AGGRESSIVE,
                'extended': ScanMode.EXTENDED,
                'keenetic': ScanMode.KEENETIC,
                'universal': ScanMode.UNIVERSAL
            }
            mode = mode_map.get(config['mode'], ScanMode.STANDARD)
            
            engine = ScannerEngine(
                target=config['target'],
                mode=mode,
                timeout=config['timeout'],
                max_workers=config['workers'],
                event_callback=self._event_callback,
                ports=config['ports'],max_hosts=config['max_hosts'],
                udp=config['udp'],cve_lookup=config['cve_lookup'],
                device_model=config['device_model'],firmware=config['firmware'],service_map=config['service_map']
            )
            
            # Передаём cancel_event
            engine._cancel_event = self.cancel_event
            
            result = engine.scan()
            
            label = re.sub(r'[^A-Za-z0-9_-]+','_',config['target'])[:80] or 'target'
            prefix = f"scan_{label}_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
            
            if config['format'] in ["html", "all"]:
                generate_html_report(result, f"{prefix}.html")
                self._log(f"📄 HTML report: {prefix}.html", 'success')
                
            if config['format'] in ["json", "all"]:
                generate_json_report(result, f"{prefix}.json")
                self._log(f"📄 JSON report: {prefix}.json", 'success')
            
            critical = sum(1 for v in result.vulnerabilities if v.risk.value == "CRITICAL")
            high = sum(1 for v in result.vulnerabilities if v.risk.value == "HIGH")
            
            if critical > 0:
                self._log(f"⚠️ CRITICAL: {critical}", 'critical')
            if high > 0:
                self._log(f"⚠️ HIGH: {high}", 'warning')
            
            state = result.stats.get('status','unknown')
            self._update_status(f"{state}: {len(result.vulnerabilities)} findings; {len(result.errors)} errors")
            for error in result.errors:
                self._log(f"{error['module']}: {error['message']}", 'warning')
        except Exception as e:
            self._log(f"❌ Error: {e}", 'error')
            self._update_status(f"Error: {e}")
        finally:
            self._set_buttons(False)


# =======================================================
#  MAIN
# =======================================================

if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerGUI(root)
    
    def on_closing():
        if app.is_scanning:
            app.cancel_event.set()
            app._update_status("Stopping before close…")
            def finish_close():
                if app.scan_thread and app.scan_thread.is_alive():
                    app.root.after(100, finish_close)
                else:
                    app.root.destroy()
            finish_close()
        else:
            app.root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()