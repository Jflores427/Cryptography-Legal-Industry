from oqs import Signature
#generate keypair for MAYO-3
def generate_signature_keypair():
    sig = Signature("MAYO-3")
    public_key = sig.generate_keypair()
    private_key = sig.export_secret_key()
    sig.close()
    return public_key, private_key
    
#sign data using MAYO-3
def sign_data(data, private_key):
    sig = Signature("MAYO-3")
    sig.import_secret_key(private_key)
    signature = sig.sign(data)
    sig.close()
    return signature
    
#verify a signature using MAYO-3
def verify_signature(data, signature, public_key):
    sig = Signature("MAYO-3")
    is_valid = sig.verify(data, signature, public_key)
    sig.close()
    return is_valid
