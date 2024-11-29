import oqs

# encapsulates key(server-side)
# returns the public-key and private key used to encapsulate, ciphertext, and the shared secret
def encap():
    kemalg = "ML-KEM-768"
    # server's only purpose is to encapsulate the key
    with oqs.KeyEncapsulation(kemalg) as server:
        
        # Client generates its key pair
        with oqs.KeyEncapsulation(kemalg) as client:
            public_key_client, private_key_client = client.generate_keypair()

        # Server encapsulates its secret using the client's public key
        ciphertext, server_shared_secret = server.encap_secret(public_key_client)
        
        return public_key_client, private_key_client, ciphertext, server_shared_secret


# decapsulates key (client-side)
# returns the shared_secret obtained from the cipher text
def decap(ciphertext, private_key_client):
    kemalg = "ML-KEM-768"
    with oqs.KeyEncapsulation(kemalg) as client:
        # Use the existing private key for decapsulation
        client.load_private_key(private_key_client)

        # The client decapsulates the server's ciphertext using its private key
        client_shared_secret = client.decap_secret(ciphertext)
        
        return client_shared_secret


# Example
# public_key_client, private_key_client, ciphertext, server_shared_secret = encap()

# # Decapsulation
# client_shared_secret = decap(ciphertext, private_key_client)

# # Validate that both shared secrets match
# print("\nShared secrets match:", server_shared_secret == client_shared_secret)
