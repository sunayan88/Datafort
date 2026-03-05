import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from pathlib import Path
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509

from database import db_queries
from crypto import ca, key_management

class AdminPanel:
    def __init__(self, admin_user, login_window):
        self.user = admin_user
        self.login_window = login_window
        
        # Initialize as Toplevel linked to login window
        self.window = tk.Toplevel(login_window)
        self.window.title(f"DATAFORT - Admin Panel ({admin_user['username']})")
        self.window.geometry("1000x700")
        
        # Handle window close
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        notebook = ttk.Notebook(self.window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tab 1: Certificate Requests
        self.cert_frame = ttk.Frame(notebook)
        notebook.add(self.cert_frame, text="Certificate Requests")
        self.setup_certificate_tab()
        
        # Tab 2: Restore Approvals
        self.restore_frame = ttk.Frame(notebook)
        notebook.add(self.restore_frame, text="Restore Approvals")
        self.setup_restore_approval_tab()
        
        # Tab 3: User Management
        self.user_frame = ttk.Frame(notebook)
        notebook.add(self.user_frame, text="User Management")
        self.setup_user_management_tab()
        
        # Tab 4: Messages
        self.messages_frame = ttk.Frame(notebook)
        notebook.add(self.messages_frame, text="Messages")
        self.setup_messages_tab()
        
        # Status Bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(self.window, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def on_closing(self):
        """Destroys the window and returns focus to the login window."""
        self.window.destroy()

    # ---------- Certificate Tab Logic ----------
    def setup_certificate_tab(self):
        tk.Label(self.cert_frame, text="Pending Certificate Requests", font=("Arial", 14, "bold")).pack(pady=10)
        
        columns = ("ID", "Username", "Role", "Requested At")
        self.cert_tree = ttk.Treeview(self.cert_frame, columns=columns, show="headings")
        for col in columns:
            self.cert_tree.heading(col, text=col)
            self.cert_tree.column(col, width=150)
        self.cert_tree.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        btn_frame = tk.Frame(self.cert_frame)
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="View Details", command=self.view_cert_details).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Approve", command=self.approve_cert, bg="#2ecc71", fg="white").pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Reject", command=self.reject_cert, bg="#e74c3c", fg="white").pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Refresh", command=self.refresh_cert_list).pack(side=tk.LEFT, padx=5)
        
        self.cert_status = tk.Label(self.cert_frame, text="", fg="blue")
        self.cert_status.pack()
        self.refresh_cert_list()

    def refresh_cert_list(self):
        for row in self.cert_tree.get_children():
            self.cert_tree.delete(row)
        requests = db_queries.get_pending_requests()
        for req in requests:
            self.cert_tree.insert("", tk.END, values=(req['request_id'], req['username'], req['requested_role'], req['requested_at']))

    def view_cert_details(self):
        selected = self.cert_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a request")
            return
        item = self.cert_tree.item(selected[0])
        req_id = item['values'][0]
        requests = db_queries.get_pending_requests()
        req = next((r for r in requests if r['request_id'] == req_id), None)
        
        detail_win = tk.Toplevel(self.window)
        detail_win.title("Request Details")
        detail_win.geometry("600x400")
        tk.Label(detail_win, text=f"User: {req['username']} | Role: {req['requested_role']}").pack(pady=10)
        txt = tk.Text(detail_win, height=15, width=70)
        txt.insert(tk.END, f"Public Key:\n{req['public_key']}\n\nCSR Hex:\n{req['csr'].hex() if req['csr'] else 'N/A'}")
        txt.config(state=tk.DISABLED)
        txt.pack(padx=10, pady=10)

    def approve_cert(self):
        selected = self.cert_tree.selection()
        if not selected: return
        req_id = self.cert_tree.item(selected[0])['values'][0]
        req = next((r for r in db_queries.get_pending_requests() if r['request_id'] == req_id), None)
        
        try:
            ca_priv = ca.load_ca_key()
            ca_cert = ca.load_ca_cert()
            cert_der = ca.sign_csr(req['csr'], ca_priv, ca_cert, req['username'], req['requested_role'])
            if db_queries.approve_request(req_id, cert_der, self.user['user_id']):
                messagebox.showinfo("Success", "Certificate approved and issued.")
                self.refresh_cert_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed: {e}")

    def reject_cert(self):
        selected = self.cert_tree.selection()
        if not selected: return
        req_id = self.cert_tree.item(selected[0])['values'][0]
        if messagebox.askyesno("Confirm", "Reject this request?"):
            db_queries.reject_request(req_id, self.user['user_id'])
            self.refresh_cert_list()

    # ---------- Restore Tab Logic ----------
    def setup_restore_approval_tab(self):
        tk.Label(self.restore_frame, text="Pending Restore Approvals", font=("Arial", 14, "bold")).pack(pady=10)
        columns = ("ID", "Requester", "Backup File", "Reason", "Requested At")
        self.restore_tree = ttk.Treeview(self.restore_frame, columns=columns, show="headings")
        for col in columns:
            self.restore_tree.heading(col, text=col)
            self.restore_tree.column(col, width=150)
        self.restore_tree.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        btn_frame = tk.Frame(self.restore_frame)
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="Approve", command=self.approve_restore, bg="#2ecc71", fg="white").pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Reject", command=self.reject_restore, bg="#e74c3c", fg="white").pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Refresh", command=self.refresh_restore_list).pack(side=tk.LEFT, padx=5)
        self.refresh_restore_list()

    def refresh_restore_list(self):
        for row in self.restore_tree.get_children(): self.restore_tree.delete(row)
        for req in db_queries.get_pending_restore_requests():
            self.restore_tree.insert("", tk.END, values=(req['request_id'], req['requester_name'], req['file_name'], req['reason'], req['request_time']))

    def approve_restore(self):
        selected = self.restore_tree.selection()
        if not selected: return
        request_id = self.restore_tree.item(selected[0])['values'][0]
        passphrase = simpledialog.askstring("Passphrase", "Enter your passphrase to sign approval:", show='*')
        if not passphrase: return
        
        try:
            key_path = Path.home() / ".datafort" / f"{self.user['username']}_private.pem"
            private_key = key_management.load_encrypted_private_key(str(key_path), passphrase)
            approval_data = f"approve:{request_id}:{time.time()}".encode()
            signature = private_key.sign(approval_data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            
            if db_queries.approve_restore_request(request_id, self.user['user_id'], signature):
                messagebox.showinfo("Success", "Restore Approved")
                self.refresh_restore_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to sign: {e}")

    def reject_restore(self):
        selected = self.restore_tree.selection()
        if not selected: return
        req_id = self.restore_tree.item(selected[0])['values'][0]
        if messagebox.askyesno("Confirm", "Reject this restore request?"):
            db_queries.reject_restore_request(req_id, self.user['user_id'])
            self.refresh_restore_list()

    # ---------- User Management Logic ----------
    def setup_user_management_tab(self):
        tk.Label(self.user_frame, text="User Access Control", font=("Arial", 14, "bold")).pack(pady=10)
        columns = ("ID", "Username", "Role", "Created At", "Active")
        self.user_tree = ttk.Treeview(self.user_frame, columns=columns, show="headings")
        for col in columns: self.user_tree.heading(col, text=col)
        self.user_tree.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        btn_frame = tk.Frame(self.user_frame)
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="Deactivate", command=self.deactivate_selected_user).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Reactivate", command=self.reactivate_selected_user).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Revoke Cert", command=self.revoke_selected_user_cert).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Refresh", command=self.refresh_user_list).pack(side=tk.LEFT, padx=5)
        self.refresh_user_list()

    def refresh_user_list(self):
        for row in self.user_tree.get_children(): self.user_tree.delete(row)
        for u in db_queries.get_all_users():
            self.user_tree.insert("", tk.END, values=(u['user_id'], u['username'], u['role'], u['created_at'], "Yes" if u['is_active'] else "No"))

    def deactivate_selected_user(self):
        selected = self.user_tree.selection()
        if not selected: return
        uid = self.user_tree.item(selected[0])['values'][0]
        db_queries.deactivate_user(uid)
        self.refresh_user_list()

    def reactivate_selected_user(self):
        selected = self.user_tree.selection()
        if not selected: return
        uid = self.user_tree.item(selected[0])['values'][0]
        db_queries.reactivate_user(uid)
        self.refresh_user_list()

    def revoke_selected_user_cert(self):
        selected = self.user_tree.selection()
        if not selected: return
        uid, username = self.user_tree.item(selected[0])['values'][0:2]
        if messagebox.askyesno("Confirm", f"Revoke certificate for {username}?"):
            serial = db_queries.get_certificate_serial_from_user(uid)
            if serial and db_queries.revoke_certificate(serial):
                db_queries.deactivate_user(uid)
                self.refresh_user_list()
                messagebox.showinfo("Success", "Revoked and User Deactivated")

    # ---------- Messaging Tab Logic ----------
    def setup_messages_tab(self):
        tk.Label(self.messages_frame, text="System Communications", font=("Arial", 14, "bold")).pack(pady=10)
        columns = ("ID", "Date", "From", "To", "Subject", "Read")
        self.msg_tree = ttk.Treeview(self.messages_frame, columns=columns, show="headings")
        for col in columns: self.msg_tree.heading(col, text=col)
        self.msg_tree.column("ID", width=0, stretch=False)
        self.msg_tree.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        self.msg_tree.bind('<<TreeviewSelect>>', self.on_admin_message_select)
        
        btn_frame = tk.Frame(self.messages_frame)
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="Reply", command=self.reply_message).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Compose New", command=lambda: self.open_admin_compose()).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Refresh", command=self.refresh_all_messages).pack(side=tk.LEFT, padx=5)
        
        self.msg_content = tk.Text(self.messages_frame, height=8, wrap=tk.WORD, bg="#f9f9f9")
        self.msg_content.pack(fill=tk.X, padx=20, pady=10)
        self.refresh_all_messages()

    def refresh_all_messages(self):
        for row in self.msg_tree.get_children(): self.msg_tree.delete(row)
        for msg in db_queries.get_all_messages():
            self.msg_tree.insert("", tk.END, values=(msg['message_id'], msg['timestamp'], msg['sender_name'], msg['recipient_name'], msg['subject'], "Yes" if msg['is_read'] else "No"))

    def on_admin_message_select(self, event):
        selected = self.msg_tree.selection()
        if not selected: return
        msg_id = self.msg_tree.item(selected[0])['values'][0]
        msg = next((m for m in db_queries.get_all_messages() if m['message_id'] == msg_id), None)
        if msg:
            self.msg_content.delete(1.0, tk.END)
            self.msg_content.insert(tk.END, f"From: {msg['sender_name']}\nSubject: {msg['subject']}\n---\n{msg['content']}")

    def reply_message(self):
        selected = self.msg_tree.selection()
        if not selected: return
        msg_id = self.msg_tree.item(selected[0])['values'][0]
        msg = next((m for m in db_queries.get_all_messages() if m['message_id'] == msg_id), None)
        target_id = msg['recipient_id'] if msg['sender_id'] == self.user['user_id'] else msg['sender_id']
        self.open_admin_compose(target_id)

    def open_admin_compose(self, preset_recipient_id=None):
        dialog = tk.Toplevel(self.window)
        dialog.title("Compose Message")
        dialog.geometry("400x400")
        
        users = db_queries.get_all_users()
        user_list = [(u['user_id'], u['username']) for u in users if u['user_id'] != self.user['user_id']]
        
        tk.Label(dialog, text="Recipient:").pack(pady=5)
        recipient_var = tk.StringVar()
        recipient_combo = ttk.Combobox(dialog, textvariable=recipient_var, values=[u[1] for u in user_list])
        recipient_combo.pack()
        if preset_recipient_id:
            name = next((u[1] for u in user_list if u[0] == preset_recipient_id), "")
            recipient_combo.set(name)
        
        tk.Label(dialog, text="Subject:").pack(pady=5)
        subject_entry = tk.Entry(dialog, width=40)
        subject_entry.pack()
        
        tk.Label(dialog, text="Message:").pack(pady=5)
        content_text = tk.Text(dialog, height=10, width=40)
        content_text.pack()
        
        def send():
            r_name = recipient_var.get()
            r_id = next((u[0] for u in user_list if u[1] == r_name), None)
            if r_id and db_queries.send_message(self.user['user_id'], r_id, subject_entry.get(), content_text.get(1.0, tk.END)):
                messagebox.showinfo("Success", "Sent")
                dialog.destroy()
                self.refresh_all_messages()
        
        tk.Button(dialog, text="Send Message", command=send, bg="#3498db", fg="white").pack(pady=10)