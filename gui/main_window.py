import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from pathlib import Path
import secrets
import hashlib
import time
import os
import tarfile
import tempfile
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

from crypto import crypto_operations, key_management
from database import db_queries

class MainWindow:
    def __init__(self, user, login_window):
        self.user = user
        self.login_window = login_window
        self.window = tk.Toplevel()
        self.window.title(f"DATAFORT - Logged in as {user['username']} ({user['role']})")
        self.window.geometry("900x700")
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Load system public key
        self.system_public_key = key_management.load_system_public_key()
        
        notebook = ttk.Notebook(self.window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        if user['role'] != 'auditor':
            self.backup_frame = ttk.Frame(notebook)
            notebook.add(self.backup_frame, text="Backup")
            self.setup_backup_tab()
            
            self.restore_frame = ttk.Frame(notebook)
            notebook.add(self.restore_frame, text="My Restores")
            self.setup_restore_tab()
            
            if user['role'] in ['manager', 'admin']:
                self.approve_frame = ttk.Frame(notebook)
                notebook.add(self.approve_frame, text="Pending Approvals")
                self.setup_approve_tab()
        
        self.signing_frame = ttk.Frame(notebook)
        notebook.add(self.signing_frame, text="Document Signing")
        self.setup_signing_tab()
        
        # Messages tab for all users
        self.messages_frame = ttk.Frame(notebook)
        notebook.add(self.messages_frame, text="Messages")
        self.setup_messages_tab()
        
        if user['role'] in ['auditor', 'admin']:
            self.audit_frame = ttk.Frame(notebook)
            notebook.add(self.audit_frame, text="Audit Log")
            self.setup_audit_tab()
        
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(self.window, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def on_closing(self):
        self.window.destroy()
    
    def setup_backup_tab(self):
        tk.Label(self.backup_frame, text="Backup Files", font=("Arial", 14)).pack(pady=10)
        
        file_frame = tk.Frame(self.backup_frame)
        file_frame.pack(pady=5)
        tk.Label(file_frame, text="Select files to backup:").pack(side=tk.LEFT, padx=5)
        self.backup_file_path = tk.StringVar()
        tk.Entry(file_frame, textvariable=self.backup_file_path, width=50).pack(side=tk.LEFT, padx=5)
        tk.Button(file_frame, text="Browse", command=self.select_backup_files).pack(side=tk.LEFT)
        
        reason_frame = tk.Frame(self.backup_frame)
        reason_frame.pack(pady=5)
        tk.Label(reason_frame, text="Reason for backup:").pack(side=tk.LEFT, padx=5)
        self.backup_reason = tk.Entry(reason_frame, width=50)
        self.backup_reason.pack(side=tk.LEFT, padx=5)
        
        tk.Button(self.backup_frame, text="Encrypt and Backup", command=self.perform_backup, bg="lightblue").pack(pady=20)
        self.backup_status = tk.Label(self.backup_frame, text="", fg="blue")
        self.backup_status.pack()
        
        tk.Label(self.backup_frame, text="Your Recent Backups:").pack(pady=10)
        self.backup_listbox = tk.Listbox(self.backup_frame, height=6)
        self.backup_listbox.pack(fill=tk.X, padx=20)
        self.refresh_backup_list()
    
    def select_backup_files(self):
        files = filedialog.askopenfilenames(title="Select files to backup")
        if files:
            self.backup_file_path.set("; ".join(files))
    
    def refresh_backup_list(self):
        self.backup_listbox.delete(0, tk.END)
        backups = db_queries.get_user_backups(self.user['user_id'])
        for b in backups:
            self.backup_listbox.insert(tk.END, f"{b['created_at']} - {b['file_name']} ({b['status']})")
    
    def perform_backup(self):
        file_list = self.backup_file_path.get()
        reason = self.backup_reason.get()
        if not file_list:
            messagebox.showerror("Error", "Please select files to backup")
            return
        
        files = [f.strip() for f in file_list.split("; ")]
        
        passphrase = simpledialog.askstring("Passphrase", "Enter your passphrase to sign the backup:", show='*')
        if not passphrase:
            return
        
        key_path = Path.home() / ".datafort" / f"{self.user['username']}_private.pem"
        try:
            private_key = key_management.load_encrypted_private_key(str(key_path), passphrase)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load private key: {e}")
            return
        
        self.backup_status.config(text="Encrypting...")
        self.window.update()
        
        try:
            with tempfile.NamedTemporaryFile(suffix='.tar', delete=False) as tmp_tar:
                tar_path = tmp_tar.name
            with tarfile.open(tar_path, 'w') as tar:
                for f in files:
                    tar.add(f, arcname=os.path.basename(f))
            
            encrypted_data, encrypted_sym_key, iv, tag = crypto_operations.encrypt_file_for_backup(
                tar_path, self.system_public_key
            )
        except Exception as e:
            messagebox.showerror("Error", f"Backup encryption failed: {e}")
            return
        finally:
            if os.path.exists(tar_path):
                os.unlink(tar_path)
        
        display_name = f"{len(files)} files" if len(files) > 1 else os.path.basename(files[0])
        
        manifest = f"{display_name}{reason}".encode()
        manifest_hash = hashlib.sha256(encrypted_data + manifest).digest()
        signature = private_key.sign(
            manifest_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        backup_id = db_queries.insert_backup(
            user_id=self.user['user_id'],
            file_name=display_name,
            encrypted_data=encrypted_data,
            encrypted_symmetric_key=encrypted_sym_key,
            iv=iv,
            tag=tag,
            signature=signature,
            reason=reason
        )
        
        if backup_id:
            self.backup_status.config(text=f"Backup successful! ID: {backup_id}", fg="green")
            self.status_var.set("Backup completed")
            self.refresh_backup_list()
            db_queries.insert_audit_log(
                self.user['user_id'], 
                "BACKUP", 
                f"Backup ID {backup_id} - {display_name}"
            )
        else:
            self.backup_status.config(text="Backup failed", fg="red")
            messagebox.showerror("Error", "Failed to save backup to database.")
    
    def setup_restore_tab(self):
        tk.Label(self.restore_frame, text="My Restore Requests", font=("Arial", 14)).pack(pady=10)
        
        columns = ("Request ID", "Backup File", "Status", "Requested At")
        self.restore_tree = ttk.Treeview(self.restore_frame, columns=columns, show="headings")
        self.restore_tree.heading("Request ID", text="ID")
        self.restore_tree.heading("Backup File", text="Backup File")
        self.restore_tree.heading("Status", text="Status")
        self.restore_tree.heading("Requested At", text="Requested At")
        self.restore_tree.column("Request ID", width=60)
        self.restore_tree.column("Backup File", width=200)
        self.restore_tree.column("Status", width=100)
        self.restore_tree.column("Requested At", width=150)
        self.restore_tree.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        btn_frame = tk.Frame(self.restore_frame)
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="Request Restore", command=self.request_restore).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Refresh", command=self.refresh_restore_requests).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Download Restored File", command=self.download_restored).pack(side=tk.LEFT, padx=5)
        
        self.restore_status = tk.Label(self.restore_frame, text="", fg="blue")
        self.restore_status.pack()
        
        self.refresh_restore_requests()
    
    def refresh_restore_requests(self):
        for row in self.restore_tree.get_children():
            self.restore_tree.delete(row)
        requests = db_queries.get_restore_requests_by_requester(self.user['user_id'])
        for req in requests:
            self.restore_tree.insert("", tk.END, values=(
                req['request_id'],
                req['file_name'],
                req['status'],
                req['request_time']
            ))
    
    def request_restore(self):
        backups = db_queries.get_user_backups(self.user['user_id'])
        if not backups:
            messagebox.showinfo("Info", "You have no backups yet.")
            return
        
        select_win = tk.Toplevel(self.window)
        select_win.title("Select Backup to Restore")
        select_win.geometry("400x300")
        
        tk.Label(select_win, text="Select a backup:").pack(pady=5)
        listbox = tk.Listbox(select_win)
        listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        backup_map = {}
        for b in backups:
            display = f"{b['backup_id']}: {b['file_name']} - {b['created_at']}"
            listbox.insert(tk.END, display)
            backup_map[display] = b['backup_id']
        
        def on_select():
            selection = listbox.curselection()
            if not selection:
                return
            display = listbox.get(selection[0])
            backup_id = backup_map[display]
            
            success = db_queries.create_restore_request(backup_id, self.user['user_id'])
            if success:
                messagebox.showinfo("Success", "Restore request submitted. Waiting for approval.")
                db_queries.insert_audit_log(self.user['user_id'], "RESTORE_REQUEST", f"Backup ID {backup_id}")
                select_win.destroy()
                self.refresh_restore_requests()
            else:
                messagebox.showerror("Error", "Failed to create request.")
        
        tk.Button(select_win, text="Submit Request", command=on_select).pack(pady=5)
    
    def download_restored(self):
        selected = self.restore_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a restore request")
            return
        item = self.restore_tree.item(selected[0])
        request_id = item['values'][0]

        # Fetch request details
        conn = db_queries.get_db_connection()
        if not conn:
            return
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT rr.status, rr.approver_id, rr.approver_signature, b.*
            FROM restore_requests rr
            JOIN backups b ON rr.backup_id = b.backup_id
            WHERE rr.request_id = %s
        """, (request_id,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()

        if not result:
            messagebox.showerror("Error", "Request not found")
            return

        if result['status'] != 'approved':
            messagebox.showerror("Error", "This request is not yet approved")
            return

        # --- New: Verify approval signature ---
        if result['approver_id'] and result['approver_signature']:
            approver = db_queries.get_user_by_id(result['approver_id'])
            if not approver:
                messagebox.showerror("Error", "Approver not found")
                return
            try:
                approver_pub_key = serialization.load_pem_public_key(approver['public_key'].encode(), default_backend())
                if not crypto_operations.verify_approval_signature(approver_pub_key, request_id, result['approver_signature']):
                    messagebox.showerror("Error", "Approval signature is invalid – possible tampering")
                    return
            except Exception as e:
                messagebox.showerror("Error", f"Signature verification failed: {e}")
                return
        else:
            messagebox.showerror("Error", "Missing approver information")
            return
        # --- End of new code ---

        save_dir = filedialog.askdirectory(title="Select directory to extract files")
        if not save_dir:
            return
        
        try:
            system_private = key_management.load_system_private_key()
            plaintext = crypto_operations.decrypt_file_for_restore(
                result['encrypted_data'],
                result['encrypted_symmetric_key'],
                result['iv'],
                result['tag'],
                system_private
            )
            
            with tempfile.NamedTemporaryFile(suffix='.tar', delete=False) as tmp_tar:
                tmp_tar.write(plaintext)
                tar_path = tmp_tar.name
            
            with tarfile.open(tar_path, 'r') as tar:
                tar.extractall(save_dir)
            
            os.unlink(tar_path)
            messagebox.showinfo("Success", f"Files extracted to {save_dir}")
            self.restore_status.config(text="Restore successful", fg="green")
            db_queries.insert_audit_log(self.user['user_id'], "RESTORE_DOWNLOAD", f"Request ID {request_id}")
        
        except InvalidTag as e:
            messagebox.showerror("Integrity Error", 
                "Backup integrity check failed. The data may have been tampered with.")
            self.restore_status.config(text="Restore failed – integrity violation", fg="red")
        
        except Exception as e:
            messagebox.showerror("Error", f"Restore failed: {str(e)}")
            self.restore_status.config(text="Restore failed", fg="red")
    
    def setup_approve_tab(self):
        tk.Label(self.approve_frame, text="Pending Restore Approvals", font=("Arial", 14)).pack(pady=10)
        
        columns = ("Request ID", "Requester", "Backup File", "Reason", "Requested At")
        self.approve_tree = ttk.Treeview(self.approve_frame, columns=columns, show="headings")
        self.approve_tree.heading("Request ID", text="ID")
        self.approve_tree.heading("Requester", text="Requester")
        self.approve_tree.heading("Backup File", text="Backup File")
        self.approve_tree.heading("Reason", text="Reason")
        self.approve_tree.heading("Requested At", text="Requested At")
        for col in columns:
            self.approve_tree.column(col, width=120)
        self.approve_tree.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        btn_frame = tk.Frame(self.approve_frame)
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="Approve", command=self.approve_request).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Reject", command=self.reject_request).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Refresh", command=self.refresh_pending).pack(side=tk.LEFT, padx=5)
        
        self.approve_status = tk.Label(self.approve_frame, text="", fg="blue")
        self.approve_status.pack()
        
        self.refresh_pending()
    
    def refresh_pending(self):
        for row in self.approve_tree.get_children():
            self.approve_tree.delete(row)
        requests = db_queries.get_pending_restore_requests()
        for req in requests:
            self.approve_tree.insert("", tk.END, values=(
                req['request_id'],
                req['requester_name'],
                req['file_name'],
                req['reason'],
                req['request_time']
            ))
    
    def approve_request(self):
        selected = self.approve_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a request")
            return
        item = self.approve_tree.item(selected[0])
        request_id = item['values'][0]
        
        passphrase = simpledialog.askstring("Passphrase", "Enter your passphrase to sign approval:", show='*')
        if not passphrase:
            return
        
        key_path = Path.home() / ".datafort" / f"{self.user['username']}_private.pem"
        try:
            private_key = key_management.load_encrypted_private_key(str(key_path), passphrase)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load private key: {e}")
            return
        
        approval_data = f"approve:{request_id}:{time.time()}".encode()
        signature = private_key.sign(
            approval_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        success = db_queries.approve_restore_request(request_id, self.user['user_id'], signature)
        if success:
            messagebox.showinfo("Success", "Request approved")
            db_queries.insert_audit_log(self.user['user_id'], "APPROVE_RESTORE", f"Request ID {request_id}")
            self.refresh_pending()
            self.approve_status.config(text="Approved", fg="green")
        else:
            messagebox.showerror("Error", "Approval failed")
    
    def reject_request(self):
        selected = self.approve_tree.selection()
        if not selected:
            return
        request_id = self.approve_tree.item(selected[0])['values'][0]
        if messagebox.askyesno("Confirm", "Reject this restore request?"):
            success = db_queries.reject_restore_request(request_id, self.user['user_id'])
            if success:
                messagebox.showinfo("Success", "Request rejected")
                db_queries.insert_audit_log(self.user['user_id'], "REJECT_RESTORE", f"Request ID {request_id}")
                self.refresh_pending()
                self.approve_status.config(text="Rejected", fg="red")
            else:
                messagebox.showerror("Error", "Rejection failed")
    
    def setup_signing_tab(self):
        tk.Label(self.signing_frame, text="Document Signing & Verification", font=("Arial", 14)).pack(pady=10)
        
        inner_notebook = ttk.Notebook(self.signing_frame)
        inner_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        sign_frame = ttk.Frame(inner_notebook)
        inner_notebook.add(sign_frame, text="Sign Document")
        self.setup_sign_tab(sign_frame)
        
        verify_frame = ttk.Frame(inner_notebook)
        inner_notebook.add(verify_frame, text="Verify Signature")
        self.setup_verify_tab(verify_frame)
    
    def setup_sign_tab(self, parent):
        tk.Label(parent, text="Select document to sign:").pack(pady=5)
        
        file_frame = tk.Frame(parent)
        file_frame.pack(pady=5)
        self.sign_file_path = tk.StringVar()
        tk.Entry(file_frame, textvariable=self.sign_file_path, width=50).pack(side=tk.LEFT, padx=5)
        tk.Button(file_frame, text="Browse", command=self.select_sign_file).pack(side=tk.LEFT)
        
        tk.Button(parent, text="Sign Document", command=self.sign_document, bg="lightyellow").pack(pady=10)
        self.sign_status = tk.Label(parent, text="", fg="blue")
        self.sign_status.pack()
    
    def select_sign_file(self):
        file = filedialog.askopenfilename(title="Select document to sign")
        if file:
            self.sign_file_path.set(file)
    
    def sign_document(self):
        file_path = self.sign_file_path.get()
        if not file_path:
            messagebox.showerror("Error", "Please select a file to sign")
            return
        
        passphrase = simpledialog.askstring("Passphrase", "Enter your passphrase to unlock private key:", show='*')
        if not passphrase:
            return
        
        key_path = Path.home() / ".datafort" / f"{self.user['username']}_private.pem"
        try:
            private_key = key_management.load_encrypted_private_key(str(key_path), passphrase)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load private key: {e}")
            return
        
        sig_path = file_path + ".sig"
        try:
            crypto_operations.sign_file(private_key, file_path, sig_path)
            self.sign_status.config(text=f"Signed successfully! Signature saved to {sig_path}", fg="green")
            self.status_var.set("Document signed")
            db_queries.insert_audit_log(self.user['user_id'], "SIGN_DOCUMENT", f"File: {os.path.basename(file_path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Signing failed: {e}")
    
    def setup_verify_tab(self, parent):
        tk.Label(parent, text="Select document and signature file:").pack(pady=5)
        
        doc_frame = tk.Frame(parent)
        doc_frame.pack(pady=5)
        tk.Label(doc_frame, text="Document:").pack(side=tk.LEFT)
        self.verify_doc_path = tk.StringVar()
        tk.Entry(doc_frame, textvariable=self.verify_doc_path, width=40).pack(side=tk.LEFT, padx=5)
        tk.Button(doc_frame, text="Browse", command=self.select_verify_doc).pack(side=tk.LEFT)
        
        sig_frame = tk.Frame(parent)
        sig_frame.pack(pady=5)
        tk.Label(sig_frame, text="Signature:").pack(side=tk.LEFT)
        self.verify_sig_path = tk.StringVar()
        tk.Entry(sig_frame, textvariable=self.verify_sig_path, width=40).pack(side=tk.LEFT, padx=5)
        tk.Button(sig_frame, text="Browse", command=self.select_verify_sig).pack(side=tk.LEFT)
        
        tk.Button(parent, text="Verify Signature", command=self.verify_signature, bg="lightcoral").pack(pady=10)
        self.verify_status = tk.Label(parent, text="", fg="blue")
        self.verify_status.pack()
    
    def select_verify_doc(self):
        file = filedialog.askopenfilename(title="Select document")
        if file:
            self.verify_doc_path.set(file)
    
    def select_verify_sig(self):
        file = filedialog.askopenfilename(title="Select signature file", filetypes=[("Signature files", "*.sig"), ("All files", "*.*")])
        if file:
            self.verify_sig_path.set(file)
    
    def verify_signature(self):
        doc_path = self.verify_doc_path.get()
        sig_path = self.verify_sig_path.get()
        if not doc_path or not sig_path:
            messagebox.showerror("Error", "Please select both document and signature files")
            return
        
        username = simpledialog.askstring("Signer", "Enter the username of the signer:")
        if not username:
            return
        
        user = db_queries.get_user_by_username(username)
        if not user:
            messagebox.showerror("Error", "User not found")
            return
        
        public_key_pem = user['public_key'].encode('utf-8')
        try:
            public_key = serialization.load_pem_public_key(public_key_pem, default_backend())
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load public key: {e}")
            return
        
        try:
            result = crypto_operations.verify_signature(public_key, doc_path, sig_path)
            if result:
                self.verify_status.config(text="Signature is VALID", fg="green")
                self.status_var.set("Signature valid")
            else:
                self.verify_status.config(text="Signature is INVALID or document tampered", fg="red")
                self.status_var.set("Signature invalid")
        except Exception as e:
            messagebox.showerror("Error", f"Verification failed: {e}")
    
    def setup_messages_tab(self):
        tk.Label(self.messages_frame, text="Messages", font=("Arial", 14)).pack(pady=10)
        
        columns = ("ID", "Date", "From", "To", "Subject", "Read")
        self.msg_tree = ttk.Treeview(self.messages_frame, columns=columns, show="headings")
        self.msg_tree.heading("ID", text="ID")
        self.msg_tree.heading("Date", text="Date")
        self.msg_tree.heading("From", text="From")
        self.msg_tree.heading("To", text="To")
        self.msg_tree.heading("Subject", text="Subject")
        self.msg_tree.heading("Read", text="Read")
        self.msg_tree.column("ID", width=0, stretch=False)  # hidden
        self.msg_tree.column("Date", width=150)
        self.msg_tree.column("From", width=100)
        self.msg_tree.column("To", width=100)
        self.msg_tree.column("Subject", width=200)
        self.msg_tree.column("Read", width=50)
        self.msg_tree.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.msg_tree.bind('<<TreeviewSelect>>', self.on_message_select)
        
        btn_frame = tk.Frame(self.messages_frame)
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="Send Message", command=self.send_message).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Refresh", command=self.refresh_messages).pack(side=tk.LEFT, padx=5)
        
        self.msg_content = tk.Text(self.messages_frame, height=8, wrap=tk.WORD)
        self.msg_content.pack(fill=tk.X, padx=20, pady=10)
        
        self.refresh_messages()
    
    def refresh_messages(self):
        for row in self.msg_tree.get_children():
            self.msg_tree.delete(row)
        messages = db_queries.get_messages_for_user(self.user['user_id'])
        for msg in messages:
            read_status = "Yes" if msg['is_read'] else "No"
            self.msg_tree.insert("", tk.END, values=(
                msg['message_id'],
                msg['timestamp'],
                msg['sender_name'],
                msg['recipient_name'],
                msg['subject'],
                read_status
            ))
    
    def on_message_select(self, event):
        selected = self.msg_tree.selection()
        if not selected:
            return
        item = self.msg_tree.item(selected[0])
        msg_id = item['values'][0]
        # Mark as read
        db_queries.mark_message_read(msg_id)
        # Fetch full message content
        messages = db_queries.get_messages_for_user(self.user['user_id'])
        for msg in messages:
            if msg['message_id'] == msg_id:
                self.msg_content.delete(1.0, tk.END)
                self.msg_content.insert(tk.END, f"From: {msg['sender_name']}\nTo: {msg['recipient_name']}\nSubject: {msg['subject']}\n\n{msg['content']}")
                break
        self.refresh_messages()
    
    def send_message(self):
        if self.user['role'] == 'admin':
            self.open_admin_compose()
        else:
            admin_id = db_queries.get_admin_user_id()
            if not admin_id:
                messagebox.showerror("Error", "No admin user found")
                return
            self.open_compose_dialog(admin_id)
    
    def open_compose_dialog(self, recipient_id):
        dialog = tk.Toplevel(self.window)
        dialog.title("Compose Message")
        dialog.geometry("400x300")
        
        tk.Label(dialog, text="Subject:").pack(pady=5)
        subject_entry = tk.Entry(dialog, width=50)
        subject_entry.pack(pady=5)
        
        tk.Label(dialog, text="Message:").pack(pady=5)
        content_text = tk.Text(dialog, height=10, width=50)
        content_text.pack(pady=5)
        
        def send():
            subject = subject_entry.get().strip()
            content = content_text.get(1.0, tk.END).strip()
            if not subject or not content:
                messagebox.showerror("Error", "Subject and message required")
                return
            success = db_queries.send_message(self.user['user_id'], recipient_id, subject, content)
            if success:
                db_queries.insert_audit_log(self.user['user_id'], "MESSAGE_SENT", f"To user {recipient_id}: {subject}")
                messagebox.showinfo("Success", "Message sent")
                dialog.destroy()
                self.refresh_messages()
            else:
                messagebox.showerror("Error", "Failed to send message")
        
        tk.Button(dialog, text="Send", command=send).pack(pady=10)
    
    def open_admin_compose(self):
        dialog = tk.Toplevel(self.window)
        dialog.title("Compose Message")
        dialog.geometry("400x350")
        
        users = db_queries.get_all_users()
        user_list = [(u['user_id'], u['username']) for u in users if u['user_id'] != self.user['user_id']]
        if not user_list:
            messagebox.showerror("Error", "No other users")
            return
        
        tk.Label(dialog, text="Recipient:").pack(pady=5)
        recipient_var = tk.StringVar()
        recipient_combo = ttk.Combobox(dialog, textvariable=recipient_var, values=[u[1] for u in user_list])
        recipient_combo.pack(pady=5)
        
        tk.Label(dialog, text="Subject:").pack(pady=5)
        subject_entry = tk.Entry(dialog, width=50)
        subject_entry.pack(pady=5)
        
        tk.Label(dialog, text="Message:").pack(pady=5)
        content_text = tk.Text(dialog, height=10, width=50)
        content_text.pack(pady=5)
        
        def send():
            recipient_name = recipient_var.get()
            if not recipient_name:
                messagebox.showerror("Error", "Select recipient")
                return
            recipient_id = next(u[0] for u in user_list if u[1] == recipient_name)
            subject = subject_entry.get().strip()
            content = content_text.get(1.0, tk.END).strip()
            if not subject or not content:
                messagebox.showerror("Error", "Subject and message required")
                return
            success = db_queries.send_message(self.user['user_id'], recipient_id, subject, content)
            if success:
                db_queries.insert_audit_log(self.user['user_id'], "MESSAGE_SENT", f"To {recipient_name}: {subject}")
                messagebox.showinfo("Success", "Message sent")
                dialog.destroy()
                self.refresh_messages()
            else:
                messagebox.showerror("Error", "Failed to send message")
        
        tk.Button(dialog, text="Send", command=send).pack(pady=10)
    
    def setup_audit_tab(self):
        tk.Label(self.audit_frame, text="System Audit Log", font=("Arial", 14)).pack(pady=10)
        
        # Filter frame
        filter_frame = tk.Frame(self.audit_frame)
        filter_frame.pack(pady=5)
        tk.Label(filter_frame, text="Filter by action:").pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar(value="ALL")
        actions = ["ALL", "LOGIN", "BACKUP", "RESTORE_REQUEST", "APPROVE_RESTORE", "REJECT_RESTORE", "SIGN_DOCUMENT", "MESSAGE_SENT"]
        filter_combo = ttk.Combobox(filter_frame, textvariable=self.filter_var, values=actions, state="readonly")
        filter_combo.pack(side=tk.LEFT, padx=5)
        filter_combo.bind('<<ComboboxSelected>>', lambda e: self.refresh_audit_log())
        
        columns = ("ID", "Time", "User", "Action", "Details")
        self.audit_tree = ttk.Treeview(self.audit_frame, columns=columns, show="headings")
        self.audit_tree.heading("ID", text="ID")
        self.audit_tree.heading("Time", text="Timestamp")
        self.audit_tree.heading("User", text="User")
        self.audit_tree.heading("Action", text="Action")
        self.audit_tree.heading("Details", text="Details")
        self.audit_tree.column("ID", width=0, stretch=False)
        self.audit_tree.column("Time", width=150)
        self.audit_tree.column("User", width=100)
        self.audit_tree.column("Action", width=120)
        self.audit_tree.column("Details", width=400)
        self.audit_tree.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        btn_frame = tk.Frame(self.audit_frame)
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="Refresh", command=self.refresh_audit_log).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Verify Selected", command=self.verify_audit_entry).pack(side=tk.LEFT, padx=5)
        
        self.audit_status = tk.Label(self.audit_frame, text="", fg="blue")
        self.audit_status.pack()
        
        self.refresh_audit_log()
    
    def refresh_audit_log(self):
        for row in self.audit_tree.get_children():
            self.audit_tree.delete(row)
        logs = db_queries.get_audit_logs()
        filter_action = self.filter_var.get()
        for log in logs:
            if filter_action != "ALL" and log['action'] != filter_action:
                continue
            self.audit_tree.insert("", tk.END, values=(
                log['log_id'],
                log['timestamp'],
                log['username'],
                log['action'],
                log['details']
            ))
    
    def verify_audit_entry(self):
        selected = self.audit_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Select a log entry")
            return
        item = self.audit_tree.item(selected[0])
        log_id = item['values'][0]
        
        log = db_queries.get_audit_log_by_id(log_id)
        if not log:
            messagebox.showerror("Error", "Log not found")
            return
        
        timestamp_str = log['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        data_str = f"{log['user_id']}|{log['action']}|{log['details']}|{timestamp_str}".encode()
        from crypto.key_management import verify_with_system_key
        if verify_with_system_key(log['signature'], data_str):
            messagebox.showinfo("Success", "Signature is valid")
        else:
            messagebox.showerror("Error", "Signature is INVALID – log may have been tampered")