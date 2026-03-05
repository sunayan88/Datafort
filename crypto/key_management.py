import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID

# ---------- User Key Management ----------
def generate_key_pair():
    """Generate RSA key pair and return private key object, private PEM, public PEM."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key, private_pem.decode('utf-8'), public_pem.decode('utf-8')

def encrypt_private_key(private_key_pem, passphrase):
    """Encrypt a private key PEM with a passphrase using PBKDF2 and AES."""
    passphrase_bytes = passphrase.encode('utf-8')
    encryption_algorithm = serialization.BestAvailableEncryption(passphrase_bytes)
    
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    
    encrypted_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )
    
    return encrypted_pem.decode('utf-8')

def save_encrypted_private_key(encrypted_pem, filepath):
    """Save encrypted private key to a file."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w') as f:
        f.write(encrypted_pem)

def load_encrypted_private_key(filepath, passphrase):
    """Load and decrypt private key from file."""
    with open(filepath, 'rb') as f:
        encrypted_pem = f.read()
    private_key = serialization.load_pem_private_key(
        encrypted_pem,
        password=passphrase.encode('utf-8'),
        backend=default_backend()
    )
    return private_key

def generate_csr(private_key, username):
    """Generate a CSR for the given username."""
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])
    
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        subject
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    return csr.public_bytes(serialization.Encoding.DER)

# ---------- System Key Management (for backup encryption) ----------
SYSTEM_KEY_PATH = Path.home() / ".datafort" / "system_private.pem"
SYSTEM_PUBLIC_KEY_PATH = Path.home() / ".datafort" / "system_public.pem"

def generate_system_key_pair():
    """Generate system key pair for encrypting backup symmetric keys."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    os.makedirs(SYSTEM_KEY_PATH.parent, exist_ok=True)
    with open(SYSTEM_KEY_PATH, 'wb') as f:
        f.write(private_pem)
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(SYSTEM_PUBLIC_KEY_PATH, 'wb') as f:
        f.write(public_pem)
    
    print(f"System private key saved to {SYSTEM_KEY_PATH}")
    print(f"System public key saved to {SYSTEM_PUBLIC_KEY_PATH}")

def load_system_private_key():
    """Load system private key."""
    with open(SYSTEM_KEY_PATH, 'rb') as f:
        pem_data = f.read()
    private_key = serialization.load_pem_private_key(
        pem_data,
        password=None,
        backend=default_backend()
    )
    return private_key

def load_system_public_key():
    """Load system public key."""
    with open(SYSTEM_PUBLIC_KEY_PATH, 'rb') as f:
        pem_data = f.read()
    public_key = serialization.load_pem_public_key(
        pem_data,
        backend=default_backend()
    )
    return public_key

def sign_with_system_key(data):
    """Sign data with system private key (for audit log)."""
    private_key = load_system_private_key()
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_with_system_key(signature, data):
    """Verify signature with system public key."""
    public_key = load_system_public_key()
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False