from oqs import KeyEncapsulation
import os
import sys

sys.path.append("liboqs-python/oqs")

# encapsulates key(server-side)
# returns ciphertext, newly combined key, and the client object
# private_key is the AES key 
def encapsulate(private_key):
    kemalg = "ML-KEM-768"
    # server's only purpose is to encapsulate the key
    with KeyEncapsulation(kemalg) as server:
        
        # Client generates its key pair
        with KeyEncapsulation(kemalg, private_key) as client:
            public_key_client = client.generate_keypair()

        # Server encapsulates its secret using the client's public key
        ciphertext, combined_key = encapsulate_aes_key(private_key, public_key_client, client)
        # storing the combined key into a file
        with open("encryption/combined.key", "wb") as f:
            f.write(combined_key)
        
        return ciphertext, client


# decapsulates key
# client object is passed in so that the same private key can be used to decapsulate
# returns the shared_secret obtained from the cipher text
def decap(ciphertext, client_obj):

    with open("encryption/combined.key", "rb") as f:
        combined_key = f.read()
    # The client decapsulates the server's ciphertext using its private key
    client_shared_secret = client_obj.decap_secret(ciphertext)
    aes = decapsulate_aes_key(client_shared_secret, combined_key)
    return aes

# Encrypt and Encapsulate an AES Key
def encapsulate_aes_key(aes_key, public_key, kem):
    # Generate a shared secret and ciphertext
    ciphertext, kem_shared_secret = kem.encap_secret(public_key)

    # Combine both the AES key and the KEM's shared secret
    combined_key = aes_key + kem_shared_secret


    return ciphertext, combined_key


# Decrypt and Retrieve AES Key
def decapsulate_aes_key(kem_shared_secret, combined_key):
    # Extract AES key from the combined key
    aes_key = combined_key[:len(combined_key) - len(kem_shared_secret)]

    return aes_key


# Example Usage
# def main():
#     # Simulate a randomly generated 256-bit AES key
#     aes_key = os.urandom(32)
#     # Encapsulation process (server-side)
#     ciphertext, combined_key, client_obj = encapsulate(aes_key)

#     # Decapsulation process (client-side)
#     aes_key_decap = decap(ciphertext, client_obj)

#     # Validate that both the aes key remains the same after decapsulating
#     print("\n AES keys match:", aes_key == aes_key_decap)

# main()