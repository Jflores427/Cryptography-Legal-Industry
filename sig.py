from oqs import Signature

# generate keypair with MAYO-3
def generate_signature_keypair():
    sig = Signature("MAYO-3")
    public_key = sig.generate_keypair()
    private_key = sig.export_secret_key()
    sig.free()
    return public_key, private_key

# sign data using the specified private key
def sign_data(data, private_key):
    sig = Signature("MAYO-3", secret_key=private_key)
    signature = sig.sign(data.encode())
    sig.free()
    return signature

# verify the signature using the public key
def verify_signature(data, signature, public_key):
    sig = Signature("MAYO-3")
    is_valid = sig.verify(data.encode(), signature, public_key)
    sig.free()
    return is_valid
