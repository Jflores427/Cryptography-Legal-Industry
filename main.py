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
)

def main():
    # Directory and file setup
    if not os.path.exists("encryption"):
        os.makedirs("encryption")
    
    document_path = "encryption/document.txt"
    encrypted_file_path = "encryption/encrypted_file.enc"
    signature_file_path = "encryption/signature.hash"
    encrypted_aes_key_path = "encryption/encrypted_AES_key"

    # Create a sample document
    with open(document_path, "w") as f:
        f.write("This is a confidential document for testing encryption, signing, and KEM.")
    print("\nDocument created.")

    # Generate signature keys
    public_key, private_key = generate_signature_keypair()

    # Sign the document
    with open(document_path, "r") as f:
        document_content = f.read()
    signature = sign_data(document_content, private_key)
    with open(signature_file_path, "wb") as f:
        f.write(signature)
    print("Document signed. Signature saved.")

    # Generate an AES symmetric key
    aes_key = generate_key_symmetric()

    # Encrypt the document with AES
    encrypt_file_symmetric(document_path, aes_key)
    print(f"Document encrypted. Encrypted file saved at {encrypted_file_path}")

    # Encapsulate the AES key using KEM
    ciphertext, client = encapsulate(aes_key)
    with open(encrypted_aes_key_path, "wb") as f:
        f.write(ciphertext)
    print(f"AES key encapsulated. Ciphertext saved at {encrypted_aes_key_path}")

    # Client-side operations
    print("\nClient-Side Operations")
    
    # Step 6: Decapsulate the AES key
    with open(encrypted_aes_key_path, "rb") as f:
        ciphertext = f.read()
    recovered_aes_key = decap(ciphertext, client)
    print("AES key successfully decapsulated.")

    # Step 7: Decrypt the file using the recovered AES key
    decrypt_file_symmetric(encrypted_file_path, recovered_aes_key)
    decrypted_file_path = encrypted_file_path[:-4] + "_decoded.txt"
    print(f"File decrypted. Decrypted file saved at {decrypted_file_path}")

    # Step 8: Verify the signature on the decrypted file's content
    with open(decrypted_file_path, "r") as f:
        decrypted_content = f.read()
    is_valid = verify_signature(decrypted_content, signature, public_key)

    if is_valid:
        print("Signature verification successful. Document integrity confirmed.")
    else:
        print("Signature verification failed. Document integrity compromised.")

    print("\nAll operations completed successfully")


if __name__ == "__main__":
    main()
