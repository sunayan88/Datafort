import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.key_management import generate_system_key_pair

if __name__ == "__main__":
    generate_system_key_pair()
    print("System keys generated in ~/.datafort/")