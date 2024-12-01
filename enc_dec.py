import gnupg
import sys 
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

sys.path.append("liboqs-python/oqs")
gpg = gnupg.GPG()

# For simplicity: Passphrase is self-enclosed in several gpg functions, otherwise the user would need to input it.
# We will assume user is entering data in the correct form, referring to name and email parameters.

def key_exists(name: str, email: str):
    uid = f'{name} <{email}>'
    keys = gpg.list_keys(keys=uid)
    for key in keys:
        if key['uids'][0] == uid:
            return (True, key["keyid"])
    return (False, None)

def key_exists_fingerprint(fingerprint: object):
    keys = gpg.list_keys()
    for key in keys:
        if key['fingerprint'] == str(fingerprint):
            return (True, key['keyid'])
    return (False, None)


def generate_key_asymmetric(name: str, email: str):
    secure_passphrase = "wb8ipm9ir7mxu8uzb61nc7pomiq3bu"
    # Check if the asymmetric key pair with these credentials exist
    exists, key_id = key_exists(name, email)
    if exists:
        return key_id
    
    # File Encryption size is limited by the key_length for RSA
    key_input =  gpg.gen_key_input(key_type="RSA", key_length="1024", key_usage="encrypt", name_real=name, name_email= email, passphrase=secure_passphrase)
    master_key_fingerprint = gpg.gen_key(key_input)
    exists, master_key_id = key_exists_fingerprint(master_key_fingerprint)

    return master_key_id

def generate_key_symmetric():
    # Create a random 32 byte sequence for the symmetric key
    symmetric_key = os.urandom(32)

    # Save the key in a secure place (for now, it is a file)
    with open("encryption/aes.key", "wb") as key_f:
        key_f.write(symmetric_key)
    return symmetric_key

def encrypt_file_asymmetric(file_path: str, recipient_email: any):
    with open(file_path, 'rb') as f:
        encrypted_data = gpg.encrypt_file(
            f,
            recipients=[recipient_email],  
            output= file_path + ".gpg"
        )

        if encrypted_data.ok:
            print("Encryption successful!")
        else:
            print("Encryption failed:", encrypted_data.stderr)
            raise Exception(encrypted_data.stderr)
        return encrypted_data

def encrypt_file_symmetric(file_path: str, key: str):
    # Create a random 16 byte sequence for the initialization vector of the CBC mode
    init_vec = os.urandom(16)

    # Create the cipher with AES and CBC and extract the encryptor from it   
    cipher = Cipher(algorithms.AES(key), modes.CBC(init_vec), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, "rb") as f:
        plaintext = f.read()

    # Pad the plaintext as a multiple of the AES block size (16 bytes), use PKCS7 and pad the plaintext
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    new_plaintext = padder.update(plaintext) + padder.finalize()

    # Encrypt the newly padded data as ciphertext
    ciphertext = encryptor.update(new_plaintext) + encryptor.finalize()

    # Write the initialization vector and ciphertext to the output file for later decryption
    with open(file_path + ".enc", "wb") as f:
        f.write(init_vec + ciphertext)


def decrypt_file_asymmetric(file_path: str):
    secure_passphrase = "wb8ipm9ir7mxu8uzb61nc7pomiq3bu"
    with open(file_path, 'rb') as f:
        decrypted_data = gpg.decrypt_file(f, passphrase=secure_passphrase)
        return decrypted_data.data.decode('utf-8')

def decrypt_file_symmetric(file_path: str, key: str):
    with open(file_path, "rb") as f:
        init_vec = f.read(16)  # The first 16 bytes are employed for the Initialization Vector of the CBC
        ciphertext = f.read()

    # Create AES Cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(init_vec), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    new_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding from the plaintext
    unpadding = padding.PKCS7(algorithms.AES.block_size).unpadder()
    old_plaintext = unpadding.update(new_plaintext) + unpadding.finalize()

    # Write the plaintext to the output file
    with open(file_path[:-4] + "_decoded.txt", "wb") as f:
        f.write(old_plaintext)
    
def delete_key(key_id):
    secure_passphrase = "wb8ipm9ir7mxu8uzb61nc7pomiq3bu"
    keys = gpg.list_keys(keys=key_id)
    if keys:
        fp = keys[0]['fingerprint']
        print(gpg.delete_keys(fp, True, secure_passphrase))
        print(gpg.delete_keys(fp, False))
        
def delete_keys(name, email):
    secure_passphrase = "wb8ipm9ir7mxu8uzb61nc7pomiq3bu"
    uid = f'{name} <{email}>'
    keys = gpg.list_keys(keys=uid)
    for key in keys:
        fp = key['fingerprint']
        print(gpg.delete_keys(fp, True, passphrase=secure_passphrase))
        print(gpg.delete_keys(fp, False))

def export_public_keys(key_ids: str):
    ascii_armored_public_keys = gpg.export_keys(key_ids, False)
    gpg.export_keys(key_ids, False, output="encryption/exported_public_keys.txt")
    return ascii_armored_public_keys

def import_keys(key_data: list[str] | str):
    import_result = gpg.import_keys(key_data)
    return import_result

def import_keys_path(key_path: str):
    import_result = gpg.import_keys_file(key_path)
    return import_result

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Test Cases~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


# print("Test 1: Encrypting/Decrypting with a public and prinit_vecate key, respectively")
# name = "J"
# recipient_email = "Jef9921@nyu.edu"

# # Generate a new key based on credentials
# key_id = generate_key(name, recipient_email)

# # Encrypt and decrypt file "demo.txt"
# encrypted = encrypt_file("encryption/demo.txt", recipient_email)
# decrypted = decrypt_file("encryption/demo.txt.gpg")

# print(encrypted)
# print(decrypted)

# print("\nTest 1: Pass\n")

# print("Test 2: Encrypting with a public key only")
# # Exporting name's Public Key before removal
# ascii_armored_public_keys = export_public_keys(key_id)

# # Removal of name's Public and Prinit_vecate Key from local keyring
# delete_key(key_id)

# # Importing name's public key only
# import_result = import_keys_path("encryption/exported_public_keys.txt")
# imported_fingerprint = import_result.fingerprints[0]
# exists, key_id = key_exists_fingerprint(imported_fingerprint)

# if exists:
#     # Set the desired trust level for encryption to work
#     trust_level = "TRUST_ULTIMATE"

#     # Edit the trust level
#     gpg.trust_keys(imported_fingerprint, trust_level)


# # Encrypting a file with name's public key via email
# encrypted = encrypt_file("encryption/demo_outgoing.txt", recipient_email)

# print("\nTest 2: Pass\n")

# # cleanup
# delete_key(key_id)
# # delete_keys(name, recipient_email)

# generate_key_asymmetric("J", "Jef9921@nyu.edu")

key = generate_key_symmetric()

encrypt_file_symmetric("encryption/demo.txt", key)
decrypt_file_symmetric("encryption/demo.txt.enc", key)






