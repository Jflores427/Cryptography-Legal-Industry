import os
import gnupg

from kem import (
    initialize_kem,
    encapsulate, 
    decap
)
from sig import (
    generate_signature_keypair,
    sign_data,
    verify_signature,
)
from enc_dec import (
    generate_key_symmetric,
    encrypt_file_symmetric,
    decrypt_file_symmetric,
    generate_key_asymmetric,
    encrypt_file_asymmetric,
    decrypt_file_asymmetric,
    export_public_keys,
    import_keys_path,
    key_exists_email,
)

def interactive_menu():
    print("\nSelect an operation:")
    print("1) Encrypt a file")
    print("2) Decrypt a file")
    print("3) Encrypt a file (Asymmetric)")
    print("4) Decrypt a file (Asymmetric)")
    print("5) Sign a file")
    print("6) Verify a signature")
    print("7) Import a public key")
    print("8) Export a public key")
    print("9) List public keys on local keyring")
    print("0) Exit")
    return input("\nEnter your choice: ").strip()

def main():
    # Ensure encryption directory exists
    if not os.path.exists("encryption"):
        os.makedirs("encryption")

    gpg = gnupg.GPG()

    # Generate AES-256 key
    aes_key = generate_key_symmetric()

    # Generate Asymmetric Keys for Demo
    master_key = generate_key_asymmetric("TestUser", "TestUser@example.com")
    
    # Generate Signature key-pair for Demo
    sig_public_key, sig_private_key = generate_signature_keypair()


    # Loop until the user exits
    while True:
        choice = interactive_menu()

        if choice == "1":
            # Encrypt a file
            file_path = input("Enter the path of the file to encrypt: ").strip()
            if not os.path.exists(file_path):
                print("File not found. Please try again.")
                continue

            encrypt_file_symmetric(file_path, aes_key)
            print(f"File encrypted as {file_path}.enc.")

            # Encapsulate the AES key with KEM
            ciphertext, client = encapsulate(aes_key)
            
            # Write encrypted key to a new file
            encrypted_key_path = f"{file_path}_AES_key.enc"
            with open(encrypted_key_path, "wb") as f:
                f.write(ciphertext)
            print(f"Key encapsulated and saved as {encrypted_key_path}.")

        elif choice == "2":
            # Decrypt a file
            file_path = input("Enter the path of the encrypted file: ").strip()
            aes_key_path = f"{file_path[:-4]}_AES_key.enc"
            
            if not os.path.exists(file_path):
                print("File not found. Please try again.")
                continue

            if not os.path.exists(aes_key_path):
                print("AES key file not found. Please encrypt the file first.")
                continue
            
            # Reads file containing AES ciphertext and decapsulates it to recover the original aes key
            with open(aes_key_path, "rb") as f:
                ciphertext = f.read()
            
            recovered_aes_key = decap(ciphertext, client)
            decrypt_file_symmetric(file_path, recovered_aes_key)
            print(f"File decrypted and saved as {file_path[:-4]}_sym_decoded.txt.")

        elif choice == "3":
            # Encrypt a file (Asymmetrically)
            file_path = input("Enter the path of the file to encrypt: ").strip()
            if not os.path.exists(file_path):
                print("File not found. Please try again.")
                continue

            email_recipient = input("Enter the email recipient for encryption (Refer to 9) for available emails): ").strip()
            if not key_exists_email(email_recipient):
                print("Recipient not found. Please try again.")
                continue

            encrypt_file_asymmetric(file_path, email_recipient)
            print(f"File encrypted as {file_path}.gpg.")

        elif choice == "4":
            # Decrypt a file (Asymmetrically)
            file_path = input("Enter the path of the encrypted file: ").strip()
            
            if not os.path.exists(file_path):
                print("File not found. Please try again.")
                continue

            decrypt_file_asymmetric(file_path)
            print(f"File decrypted and saved as {file_path[:-4]}_asym_decoded.txt.")

        elif choice == "5":
            # Sign a file
            file_path = input("Enter the path of the file to sign: ").strip()
            if not os.path.exists(file_path):
                print("File not found. Please try again.")
                continue

            with open(file_path, "r") as f:
                content = f.read()

            signature = sign_data(content, sig_private_key)
         
            signature_path = f"{file_path}.sig"
            with open(signature_path, "wb") as f:
                f.write(signature)
            print(f"File signed. Signature saved as {signature_path}.")

        elif choice == "6":
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

            is_valid = verify_signature(content, signature, sig_public_key)

            if is_valid:
                print("Signature verified. Document integrity confirmed.")
            else:
                print("Signature verification failed. Document integrity compromised.")

        elif choice == "7":
            # Import a public key into local keyring
            key_path = input("Enter the path of the public key file to import: ").strip()
            if not os.path.exists(key_path):
                print("Public key file not found. Please try again.")
                continue

            result = import_keys_path(key_path)
            if result.fingerprints:
                print("Public key imported successfully.")
            else:
                print("Failed to import the public key.")

        elif choice == "8":
            # Export a public key into a file
            key_id = input("Enter the ID of the key to export: ").strip()
            ascii_armored_public_keys = export_public_keys(key_id)

            if not ascii_armored_public_keys:
                print(f"Public key export failed.")
            else:
                export_path = f"encryption/{key_id[:8]}.txt"
                print(f"Public key exported to {export_path}.")
        
        elif choice == "9":
            # List all public keys on local keyring
            keys = gpg.list_keys()
            for key in keys:
               print(f'\nKey ID:{key['keyid']}\nUser ID:{key['uids'][0]}\nFingerprint:{key['fingerprint']}')

        elif choice == "0":
            print("Exiting")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
