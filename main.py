import os
from kem import encapsulate, decap
from sig import (
    generate_signature_keypair,
    sign_data,
    verify_signature,
)
from enc_dec import (
    generate_key_symmetric,
    encrypt_file_symmetric,
    decrypt_file_symmetric,
    export_public_keys,
    import_keys_path,
)

def interactive_menu():
    print("\nSelect an operation:")
    print("1) Encrypt a file")
    print("2) Decrypt a file")
    print("3) Sign a file")
    print("4) Verify a signature")
    print("5) Import a public key")
    print("6) Export a public key")
    print("0) Exit")
    return input("\nEnter your choice: ").strip()

def main():
    # Ensure encryption directory exists
    if not os.path.exists("encryption"):
        os.makedirs("encryption")

    # Loop until the user exits
    while True:
        choice = interactive_menu()

        if choice == "1":
            # Encrypt a file
            file_path = input("Enter the path of the file to encrypt: ").strip()
            if not os.path.exists(file_path):
                print("File not found. Please try again.")
                continue

            aes_key = generate_key_symmetric()
            encrypt_file_symmetric(file_path, aes_key)
            print(f"File encrypted as {file_path}.enc.")

            # Encapsulate the AES key with KEM
            ciphertext, client = encapsulate(aes_key)
            encrypted_key_path = f"{file_path}_AES_key.enc"
            with open(encrypted_key_path, "wb") as f:
                f.write(ciphertext)
            print(f"Key encapsulated and saved as {encrypted_key_path}.")

        elif choice == "2":
            # Decrypt a file
            file_path = input("Enter the path of the encrypted file: ").strip()
            aes_key_path = f"{file_path}_AES_key.enc"
            if not os.path.exists(file_path) or not os.path.exists(aes_key_path):
                print("File or AES key not found. Please try again.")
                continue

            with open(aes_key_path, "rb") as f:
                ciphertext = f.read()
            recovered_aes_key = decap(ciphertext, client)
            decrypt_file_symmetric(file_path, recovered_aes_key)
            print(f"File decrypted and saved as {file_path[:-4]}_decoded.txt.")

        elif choice == "3":
            # Sign a file
            file_path = input("Enter the path of the file to sign: ").strip()
            if not os.path.exists(file_path):
                print("File not found. Please try again.")
                continue

            public_key, private_key = generate_signature_keypair()
            with open(file_path, "r") as f:
                content = f.read()
            signature = sign_data(content, private_key)
            signature_path = f"{file_path}.sig"
            with open(signature_path, "wb") as f:
                f.write(signature)
            print(f"File signed. Signature saved as {signature_path}.")

        elif choice == "4":
            # Verify a signature
            file_path = input("Enter the path of the file to verify: ").strip()
            signature_path = f"{file_path}.sig"
            if not os.path.exists(file_path) or not os.path.exists(signature_path):
                print("File or signature not found. Please try again.")
                continue

            with open(file_path, "r") as f:
                content = f.read()
            with open(signature_path, "rb") as f:
                signature = f.read()

            is_valid = verify_signature(content, signature, public_key)
            if is_valid:
                print("Signature verified. Document integrity confirmed.")
            else:
                print("Signature verification failed. Document integrity compromised.")

        elif choice == "5":
            # Import a public key
            key_path = input("Enter the path of the public key file to import: ").strip()
            if not os.path.exists(key_path):
                print("Public key file not found. Please try again.")
                continue

            result = import_keys_path(key_path)
            if result.fingerprints:
                print("Public key imported successfully.")
            else:
                print("Failed to import the public key.")

        elif choice == "6":
            # Export a public key
            key_id = input("Enter the ID of the key to export: ").strip()
            export_path = "encryption/exported_public_keys.txt"
            export_public_keys(key_id)
            print(f"Public key exported to {export_path}.")

        elif choice == "0":
            print("Exiting")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
