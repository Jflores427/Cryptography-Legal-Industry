from oqs import Signature

#generate keypair for MAYO-3
def generate_signature_keypair():
    with Signature("MAYO-3") as sig:
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
    return public_key, private_key

#sign data using MAYO-3
def sign_data(data, private_key):
    with Signature("MAYO-3") as sig:
        sig.import_secret_key(private_key)
        signature = sig.sign(data)
    return signature

#verify a signature using MAYO-3
def verify_signature(data, signature, public_key):
    with Signature("MAYO-3") as sig:
        is_valid = sig.verify(data, signature, public_key)
    return is_valid
