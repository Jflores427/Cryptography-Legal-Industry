import os
from kem import encapsulate, decap
from sig import (
    generate_signature_keypair, 
    sign_data, 
    verify_signature
)
from enc_dec import (
    generate_key_asymmetric,
    generate_key_symmetric,
    encrypt_file_asymmetric,
    decrypt_file_asymmetric,
    encrypt_file_symmetric,
    decrypt_file_symmetric
)

def main():
    # Directories and file setup
    if not os.path.exists("encryption"):
        os.makedirs("encryption")
    demo_file = "encryption/demo.txt"
    demo_outgoing_file = "encryption/demo_outgoing.txt"
    
    # Create a demo file to use
    with open(demo_file, "w") as f:
        f.write("This is a sample demo file to test encryption and signatures.")
    with open(demo_outgoing_file, "w") as f:
        f.write("This is a second demo file to test asymmetric encryption.")
    
    print("\n--- Key Encapsulation and Decapsulation ---")
    # AES key encapsulation
    aes_key = os.urandom(32)  # Generate a random AES key
    ciphertext, client = encapsulate(aes_key)  # Encapsulate the key
    recovered_aes_key = decap(ciphertext, client)  # Decapsulate the key
    
    print(f"Original AES key: {aes_key}")
    print(f"Recovered AES key: {recovered_aes_key}")
    print("Key encapsulation successful!" if aes_key == recovered_aes_key else "Key encapsulation failed.")
    
    print("\n--- Digital Signatures ---")
    # Generate signature keys
    public_key, private_key = generate_signature_keypair()
    
    # Sign the file's content
    with open(demo_file, "r") as f:
        data = f.read()
    signature = sign_data(data, private_key)
    print("File signed successfully.")
    
    # Verify the signature
    is_valid = verify_signature(data, signature, public_key)
    print("Signature is valid." if is_valid else "Signature is invalid.")
    
    print("\n--- Asymmetric File Encryption ---")
    # Asymmetric encryption and decryption
    name = "Test User"
    email = "testuser@example.com"
    key_id = generate_key_asymmetric(name, email)
    
    # Encrypt and decrypt a file
    encrypt_file_asymmetric(demo_outgoing_file, email)
    decrypted_data = decrypt_file_asymmetric(demo_outgoing_file + ".gpg")
    print(f"Decrypted data: {decrypted_data}")
    
    print("\n--- Symmetric File Encryption ---")
    # Symmetric encryption and decryption
    symmetric_key = generate_key_symmetric()
    encrypt_file_symmetric(demo_file, symmetric_key)
    decrypt_file_symmetric(demo_file + ".enc", symmetric_key)
    print("Symmetric encryption and decryption successful.")
    
    print("\n--- All operations completed successfully ---")

if __name__ == "__main__":
    main()
