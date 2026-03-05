import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto import ca, key_management
from database import db_queries
from getpass import getpass
from pathlib import Path

def setup_admin():
    print("Setting up DATAFORT Root CA and Admin User...")
    
    if ca.load_ca_key() is not None:
        print("CA already exists. Skipping CA generation.")
    else:
        print("Generating CA key pair...")
        ca_priv = ca.generate_ca_key()
        print("Creating self-signed CA certificate...")
        ca_cert = ca.generate_self_signed_ca_cert(ca_priv)
        print("CA initialized.")
    
    print("\nNow create an admin user.")
    username = input("Admin username: ").strip()
    passphrase = getpass("Admin passphrase (min 8 chars): ")
    confirm = getpass("Confirm passphrase: ")
    if passphrase != confirm or len(passphrase) < 8:
        print("Passphrase mismatch or too short. Exiting.")
        return
    
    print("Generating admin key pair...")
    priv_obj, priv_pem, pub_pem = key_management.generate_key_pair()
    
    encrypted_priv = key_management.encrypt_private_key(priv_pem, passphrase)
    key_path = Path.home() / ".datafort" / f"{username}_private.pem"
    key_management.save_encrypted_private_key(encrypted_priv, str(key_path))
    print(f"Private key saved to {key_path}")
    
    print("Generating CSR...")
    csr_der = key_management.generate_csr(priv_obj, username)
    
    print("Signing CSR with CA...")
    ca_priv = ca.load_ca_key()
    ca_cert = ca.load_ca_cert()
    cert_der = ca.sign_csr(csr_der, ca_priv, ca_cert, username, role="admin")
    
    cert_path = Path.home() / ".datafort" / f"{username}_cert.pem"
    with open(cert_path, 'wb') as f:
        f.write(cert_der)
    print(f"Certificate saved to {cert_path}")
    
    print("Inserting admin into database...")
    success = db_queries.insert_user(username, "admin", pub_pem, cert_der)
    if success:
        print("Admin user created successfully!")
    else:
        print("Failed to insert admin user. Check database.")

if __name__ == "__main__":
    setup_admin()