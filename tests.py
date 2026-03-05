from pathlib import Path
from crypto.key_management import load_encrypted_private_key
key_path = Path.home() / ".datafort" / "testemployee_private.pem"
print("File exists:", key_path.exists())
try:
    key = load_encrypted_private_key(str(key_path), "your_passphrase_here")
    print("Private key loaded successfully")
except Exception as e:
    print("Failed to load private key:", e)