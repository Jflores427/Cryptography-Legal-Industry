from oqs import KeyEncapsulation
import os
import sys

sys.path.append("liboqs-python/oqs")

def initialize_kem():
    kemalg = "ML-KEM-768"
    with KeyEncapsulation(kemalg) as client:
        public_key = client.generate_keypair()
        private_key = client.export_secret_key()
        return client, public_key, private_key
    
# encapsulates key(server-side)
# returns ciphertext and the client object and writes the combined_key into a file
def encapsulate(aes_key):
    kemalg = "ML-KEM-768"

    with KeyEncapsulation(kemalg) as server:
            s_public_key = server.generate_keypair()

            # Client generates its key pair
            with KeyEncapsulation(kemalg) as client:
                c_public_key = client.generate_keypair()

                # Server encapsulates its secret using the client's public key
                ciphertext, combined_key = encapsulate_aes_key(aes_key, c_public_key, server)

                # storing the combined key into a file
                with open("encryption/combined.key", "wb") as f:
                    f.write(combined_key)
                
                return ciphertext, client

# Encrypt and Encapsulate an AES Key
def encapsulate_aes_key(aes_key, public_key, client):
    # Generate a shared secret and ciphertext
    ciphertext, client_shared_secret = client.encap_secret(public_key)

    # Combine both the AES key and the KEM's shared secret
    combined_key = aes_key + client_shared_secret

    return ciphertext, combined_key


# decapsulates key
# client object is passed in so that the same private key can be used to decapsulate
# returns the shared_secret obtained from the cipher text
def decap(ciphertext, client):
    with open("encryption/combined.key", "rb") as f:
        combined_key = f.read()

    # The client decapsulates the server's ciphertext using its private key
    client_shared_secret = client.decap_secret(ciphertext)
    aes = decapsulate_aes_key(client_shared_secret, combined_key)
    
    return aes


# Decrypt and Retrieve AES Key
def decapsulate_aes_key(client_shared_secret, combined_key):
    # Extract AES key from the combined key
    aes_key = combined_key[:len(combined_key) - len(client_shared_secret)]

    return aes_key

# Example Usage
def main():
    # Simulate a randomly generated 256-bit AES key
    aes_key = os.urandom(32)
    # Encapsulation process (server-side)
    ciphertext, combined_key, client_obj = encapsulate(aes_key)

    # Decapsulation process (client-side)
    aes_key_decap = decap(ciphertext, client_obj)

    # Validate that both the aes key remains the same after decapsulating
    print("\n AES keys match:", aes_key == aes_key_decap)

# main()