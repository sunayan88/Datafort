import os
from pathlib import Path
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID

CA_KEY_PATH = Path.home() / ".datafort" / "ca_private.pem"
CA_CERT_PATH = Path.home() / ".datafort" / "ca_cert.pem"

def generate_ca_key():
    """Generate CA RSA key pair and save private key (unencrypted for simplicity)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    os.makedirs(CA_KEY_PATH.parent, exist_ok=True)
    with open(CA_KEY_PATH, 'wb') as f:
        f.write(pem)
    return private_key

def load_ca_key():
    """Load CA private key from file."""
    if not CA_KEY_PATH.exists():
        return None
    with open(CA_KEY_PATH, 'rb') as f:
        pem_data = f.read()
    private_key = serialization.load_pem_private_key(
        pem_data,
        password=None,
        backend=default_backend()
    )
    return private_key

def generate_self_signed_ca_cert(private_key):
    """Create a self-signed CA certificate."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "DATAFORT Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DATAFORT"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    with open(CA_CERT_PATH, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert

def load_ca_cert():
    """Load CA certificate from file."""
    if not CA_CERT_PATH.exists():
        return None
    with open(CA_CERT_PATH, 'rb') as f:
        pem_data = f.read()
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    return cert

def sign_csr(csr_der, ca_private_key, ca_cert, username, role):
    """Sign a CSR and return a DER-encoded certificate."""
    csr = x509.load_der_x509_csr(csr_der, default_backend())
    
    cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(username)]), critical=False
    ).sign(ca_private_key, hashes.SHA256(), default_backend())
    
    return cert.public_bytes(serialization.Encoding.DER)