import sys
from kem import encap, decap
from sig import generate_signature_keypair, sign_data, verify_signature
from enc_dec import (
    generate_key,
    encrypt_file,
    decrypt_file,
    export_public_keys,
    import_keys_path,
    delete_key,
    key_exists_fingerprint,
)
# Key Encapsulation and Shared Secret Exchange
print("Key Encapsulation")
public_key_client, private_key_client, ciphertext, server_shared_secret = encap()
client_shared_secret = decap(ciphertext, private_key_client)
