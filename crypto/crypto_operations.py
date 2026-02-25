import os
import secrets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ---------- Document Signing ----------
def sign_file(private_key, file_path, signature_path):
    """Sign a file using private key and save signature."""
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(file_data)
    file_hash = digest.finalize()
    
    signature = private_key.sign(
        file_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    with open(signature_path, 'wb') as f:
        f.write(signature)
    return True

def verify_signature(public_key, file_path, signature_path):
    """Verify file signature using public key."""
    with open(file_path, 'rb') as f:
        file_data = f.read()
    with open(signature_path, 'rb') as f:
        signature = f.read()
    
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(file_data)
    file_hash = digest.finalize()
    
    try:
        public_key.verify(
            signature,
            file_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# ---------- Backup Encryption ----------
def encrypt_file_for_backup(file_path, system_public_key):
    """
    Encrypt a file using a random symmetric key (AES-256-GCM),
    then encrypt that symmetric key with the system public key.
    Returns (encrypted_data, encrypted_symmetric_key, iv, tag)
    """
    symmetric_key = secrets.token_bytes(32)  # AES-256 key
    iv = secrets.token_bytes(12)  # GCM recommended nonce length
    
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    
    encrypted_symmetric_key = system_public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return ciphertext, encrypted_symmetric_key, iv, tag

def decrypt_file_for_restore(encrypted_data, encrypted_symmetric_key, iv, tag, system_private_key):
    """
    Decrypt a backup file using system private key to get the symmetric key,
    then decrypt the data.
    """
    symmetric_key = system_private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
    return plaintext