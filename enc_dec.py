import gnupg
import sys 
sys.path.append("liboqs-python/oqs")

gpg = gnupg.GPG()

with open('demo.txt', 'rb') as f:
    encrypted_data = gpg.encrypt_file(
        f,
        recipients=['randomAddress@example.com'],  
        output='demo.txt.gpg'
    )

with open('demo.txt.gpg', 'rb') as f:
    decrypted_data = gpg.decrypt_file(f)
    print(decrypted_data.data.decode('utf-8'))