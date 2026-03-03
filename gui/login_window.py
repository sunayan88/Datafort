import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
import secrets
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509

from crypto import key_management
from database import db_queries
from gui.register_window import RegisterWindow
from crypto.bruteforce import check_account_locked, handle_failed_login, handle_successful_login

class LoginWindow:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("DATAFORT - Secure Enterprise Backup")
        self.window.geometry("500x400")
        self.window.resizable(False, False)
        self.center_window()
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('Title.TLabel', font=('Arial', 18, 'bold'))
        self.style.configure('Heading.TLabel', font=('Arial', 12))
        self.style.configure('Login.TButton', font=('Arial', 11), padding=10)
        
        main_frame = ttk.Frame(self.window, padding="30")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="DATAFORT", style='Title.TLabel').pack(pady=(0, 10))
        ttk.Label(main_frame, text="Secure Enterprise Backup System", style='Heading.TLabel').pack(pady=(0, 30))
        
        # Username
        username_frame = ttk.Frame(main_frame)
        username_frame.pack(fill=tk.X, pady=10)
        ttk.Label(username_frame, text="Username:", font=('Arial', 10)).pack(anchor=tk.W)
        self.username_entry = ttk.Entry(username_frame, font=('Arial', 11))
        self.username_entry.pack(fill=tk.X, pady=(5, 0))
        
        # Passphrase
        passphrase_frame = ttk.Frame(main_frame)
        passphrase_frame.pack(fill=tk.X, pady=10)
        ttk.Label(passphrase_frame, text="Passphrase:", font=('Arial', 10)).pack(anchor=tk.W)
        self.passphrase_entry = ttk.Entry(passphrase_frame, show="*", font=('Arial', 11))
        self.passphrase_entry.pack(fill=tk.X, pady=(5, 0))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=30)
        ttk.Button(button_frame, text="Login", command=self.login, style='Login.TButton').pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 10))
        ttk.Button(button_frame, text="Register", command=self.open_register, style='Login.TButton').pack(side=tk.RIGHT, expand=True, fill=tk.X, padx=(10, 0))
        
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.window, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.window.bind('<Return>', lambda event: self.login())
        self.username_entry.focus()
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def center_window(self):
        self.window.update_idletasks()
        width = self.window.winfo_width()
        height = self.window.winfo_height()
        x = (self.window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.window.winfo_screenheight() // 2) - (height // 2)
        self.window.geometry(f'{width}x{height}+{x}+{y}')
    
    def on_closing(self):
        self.window.quit()
        self.window.destroy()
    
    def login(self):
        username = self.username_entry.get().strip()
        passphrase = self.passphrase_entry.get()
        
        if not username or not passphrase:
            messagebox.showerror("Error", "Please enter username and passphrase")
            return
        
        self.status_var.set("Authenticating...")
        self.window.update()
        
        user = db_queries.get_user_by_username(username)
        if not user:
            self.status_var.set("Ready")
            messagebox.showerror("Error", "User not found or inactive")
            return
        
        # Brute‑force protection: check if account is locked
        if check_account_locked(user['user_id']):
            self.status_var.set("Ready")
            messagebox.showerror("Error", "Account temporarily locked due to too many failed attempts. Try again later.")
            return
        
        # Revocation check
        try:
            cert_der = user['certificate']
            if cert_der:
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                if db_queries.is_certificate_revoked(cert.serial_number):
                    self.status_var.set("Ready")
                    messagebox.showerror("Error", "Your certificate has been revoked. Contact admin.")
                    return
        except Exception as e:
            print(f"Revocation check error: {e}")
        
        key_path = Path.home() / ".datafort" / f"{username}_private.pem"
        if not key_path.exists():
            self.status_var.set("Ready")
            messagebox.showerror("Error", "Private key file not found. Please register.")
            return
        
        try:
            private_key = key_management.load_encrypted_private_key(str(key_path), passphrase)
        except Exception:
            # Failed login (passphrase)
            handle_failed_login(username)
            self.status_var.set("Ready")
            messagebox.showerror("Error", "Invalid passphrase or corrupted key")
            return
        
        challenge = secrets.token_bytes(32)
        try:
            signature = private_key.sign(
                challenge,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            public_key_pem = user['public_key'].encode('utf-8')
            public_key = serialization.load_pem_public_key(public_key_pem, default_backend())
            
            public_key.verify(
                signature,
                challenge,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Successful login
            handle_successful_login(username)
            
            db_queries.insert_audit_log(user['user_id'], "LOGIN", f"User {username} logged in")
            
            self.status_var.set("Login successful")
            self.window.withdraw()  # Hide login window
            
            # Create and wait for appropriate main window
            if user['role'] == 'admin':
                from gui.admin_panel import AdminPanel
                admin_win = AdminPanel(user, self.window)
                self.window.wait_window(admin_win.window)
            else:
                from gui.main_window import MainWindow
                main_win = MainWindow(user, self.window)
                self.window.wait_window(main_win.window)
            
            # When main window is closed, show login again
            self.window.deiconify()
            self.username_entry.delete(0, tk.END)
            self.passphrase_entry.delete(0, tk.END)
            self.username_entry.focus()
            self.status_var.set("Ready")
            
        except Exception as e:
            # Failed login (signature verification)
            handle_failed_login(username)
            self.status_var.set("Ready")
            messagebox.showerror("Error", "Authentication failed")
    
    def open_register(self):
        RegisterWindow(self.window)
    
    def run(self):
        self.window.mainloop()