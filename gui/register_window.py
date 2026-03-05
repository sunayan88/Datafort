import tkinter as tk
from tkinter import messagebox
from pathlib import Path
from crypto import key_management
from database import db_queries

class RegisterWindow:
    def __init__(self, parent):
        self.parent = parent
        self.window = tk.Toplevel(parent)
        self.window.title("DATAFORT - User Registration")
        self.window.geometry("400x350")
        self.window.transient(parent)
        self.window.grab_set()
        
        tk.Label(self.window, text="Username:").pack(pady=5)
        self.username_entry = tk.Entry(self.window)
        self.username_entry.pack(pady=5)
        
        tk.Label(self.window, text="Requested Role:").pack(pady=5)
        self.role_var = tk.StringVar(value="employee")
        role_frame = tk.Frame(self.window)
        role_frame.pack(pady=5)
        tk.Radiobutton(role_frame, text="Employee", variable=self.role_var, value="employee").pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(role_frame, text="Manager", variable=self.role_var, value="manager").pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(role_frame, text="Auditor", variable=self.role_var, value="auditor").pack(side=tk.LEFT, padx=5)
        
        tk.Label(self.window, text="Passphrase (to encrypt your private key):").pack(pady=5)
        self.passphrase_entry = tk.Entry(self.window, show="*")
        self.passphrase_entry.pack(pady=5)
        
        tk.Label(self.window, text="Confirm Passphrase:").pack(pady=5)
        self.confirm_entry = tk.Entry(self.window, show="*")
        self.confirm_entry.pack(pady=5)
        
        tk.Button(self.window, text="Submit Registration Request", command=self.register).pack(pady=20)
        
        self.status_label = tk.Label(self.window, text="", fg="blue")
        self.status_label.pack(pady=5)
    
    def register(self):
        username = self.username_entry.get().strip()
        passphrase = self.passphrase_entry.get()
        confirm = self.confirm_entry.get()
        role = self.role_var.get()
        
        if not username:
            messagebox.showerror("Error", "Username is required")
            return
        if not passphrase:
            messagebox.showerror("Error", "Passphrase is required")
            return
        if passphrase != confirm:
            messagebox.showerror("Error", "Passphrases do not match")
            return
        if len(passphrase) < 8:
            messagebox.showerror("Error", "Passphrase must be at least 8 characters")
            return
        
        self.status_label.config(text="Checking username...")
        self.window.update()
        if db_queries.check_username_exists(username):
            messagebox.showerror("Error", "Username already exists or has a pending request")
            return
        
        try:
            self.status_label.config(text="Generating key pair...")
            self.window.update()
            
            private_key_obj, private_pem, public_pem = key_management.generate_key_pair()
            
            self.status_label.config(text="Encrypting private key...")
            self.window.update()
            encrypted_private = key_management.encrypt_private_key(private_pem, passphrase)
            
            datafort_dir = Path.home() / ".datafort"
            key_file = datafort_dir / f"{username}_private.pem"
            key_management.save_encrypted_private_key(encrypted_private, str(key_file))
            
            self.status_label.config(text="Generating Certificate Signing Request...")
            self.window.update()
            csr_der = key_management.generate_csr(private_key_obj, username)
            
            self.status_label.config(text="Submitting request...")
            self.window.update()
            success = db_queries.insert_certificate_request(username, public_pem, csr_der, role)
            
            if success:
                messagebox.showinfo("Success", 
                    f"Registration request submitted!\n\nYour private key has been saved to:\n{key_file}\n\nAn administrator will review your request and issue a certificate.")
                self.window.destroy()
            else:
                messagebox.showerror("Error", "Failed to submit request. Please try again.")
                self.status_label.config(text="")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred:\n{str(e)}")
            self.status_label.config(text="")