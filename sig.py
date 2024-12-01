import oqs

# generates a key pair for the MAYO-3 digital signature scheme. returns a tuple containing the public and private keys.
def generate_key_pair():
    mayo3_sig = oqs.Signature("MAYO-3")
    public_key, private_key = mayo3_sig.generate_keypair()
    mayo3_sig.close()
    return public_key, private_key

# signs the given message using the private key and MAYO-3. returns the digital signature.
def sign_message(message: bytes, private_key: bytes) -> bytes:
    mayo3_sig = oqs.Signature("MAYO-3")
    signature = mayo3_sig.sign(message, private_key)
    mayo3_sig.close()
    return signature

# verifies the digital signature of a message using the public key. returns True if the signature is valid, False otherwise.
def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    mayo3_sig = oqs.Signature("MAYO-3")
    is_valid = mayo3_sig.verify(message, signature, public_key)
    mayo3_sig.close()
    return is_valid
