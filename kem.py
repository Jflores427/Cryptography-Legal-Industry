from oqs import KeyEcapsulation

# encapsulates key(server-side)
# returns the public-key and private key used to encapsulate, ciphertext, the shared secret, and the client object 
def encap(private_key):
    kemalg = "ML-KEM-768"
    # server's only purpose is to encapsulate the key
    with KeyEncapsulation(kemalg, private_key) as server:
        
        # Client generates its key pair
        with KeyEncapsulation(kemalg) as client:
            public_key_client = client.generate_keypair()
            private_key_client = client.export_secret_key()

        # Server encapsulates its secret using the client's public key
        ciphertext, server_shared_secret = server.encap_secret(public_key_client)
        client_obj = client
        
        return public_key_client, private_key_client, ciphertext, server_shared_secret, client_obj


# decapsulates key
# client object is passed in so that the same private key can be used to decapsulate
# returns the shared_secret obtained from the cipher text
def decap(ciphertext, client_obj):
    # The client decapsulates the server's ciphertext using its private key
    client_shared_secret = client_obj.decap_secret(ciphertext)
    return client_shared_secret


# Example
# public_key, private_key, ciphertext, server_shared_scecret, client_obj = encap()
# client_shared_secret = decap(ciphertext, client_obj)
# # Validate that both shared secrets match
# print("\nShared secrets match:", server_shared_secret == client_shared_secret)
