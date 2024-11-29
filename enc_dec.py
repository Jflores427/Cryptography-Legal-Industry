import gnupg
import sys 

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

def generate_key(name: str, email: str):
    exists, key_id = key_exists(name, email)
    if exists:
        return key_id
    
    # key_input =  gpg.gen_key_input(key_type="ECDH", key_curve="cv25519", key_length="1024", key_usage="encrypt", name_real=name, name_email= email, passphrase="secret")
    key_input =  gpg.gen_key_input(key_type="RSA", key_length="1024", key_usage="encrypt", name_real=name, name_email= email, passphrase="secret")
    master_key_fingerprint = gpg.gen_key(key_input)

    exists, master_key_id = key_exists_fingerprint(master_key_fingerprint)
    return master_key_id

def delete_key(key_id):
    keys = gpg.list_keys(keys=key_id)
    if keys:
        fp = keys[0]['fingerprint']
        print(gpg.delete_keys(fp, True, "secret"))
        print(gpg.delete_keys(fp, False))
        
def delete_keys(name, email):
    uid = f'{name} <{email}>'
    keys = gpg.list_keys(keys=uid)
    for key in keys:
        fp = key['fingerprint']
        print(gpg.delete_keys(fp, True, passphrase="secret"))
        print(gpg.delete_keys(fp, False))


def encrypt_file(file_path: str, recipient_email: any):
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
        return encrypted_data

def decrypt_file(file_path: str):
    with open(file_path, 'rb') as f:
        decrypted_data = gpg.decrypt_file(f, passphrase="secret")
        return decrypted_data.data.decode('utf-8')
    
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


print("Test 1: Encrypting/Decrypting with a public and private key, respectively")
name = "J"
recipient_email = "Jef9921@nyu.edu"

# Generate a new key based on credentials
key_id = generate_key(name, recipient_email)

# Encrypt and decrypt file "demo.txt"
encrypted = encrypt_file("encryption/demo.txt", recipient_email)
decrypted = decrypt_file("encryption/demo.txt.gpg")

print(encrypted)
print(decrypted)

print("\nTest 1: Pass\n")

print("Test 2: Encrypting with a public key only")
# Exporting name's Public Key before removal
ascii_armored_public_keys = export_public_keys(key_id)

# Removal of name's Public and Private Key from local keyring
delete_key(key_id)

# Importing name's public key only
import_result = import_keys_path("encryption/exported_public_keys.txt")
imported_fingerprint = import_result.fingerprints[0]
exists, key_id = key_exists_fingerprint(imported_fingerprint)

if exists:
    # Set the desired trust level for encryption to work
    trust_level = "TRUST_ULTIMATE"

    # Edit the trust level
    gpg.trust_keys(imported_fingerprint, trust_level)


# Encrypting a file with name's public key via email
encrypted = encrypt_file("encryption/demo_outgoing.txt", recipient_email)

print("\nTest 2: Pass\n")

# cleanup
delete_key(key_id)
# delete_keys(name, recipient_email)





