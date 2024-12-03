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

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Test Cases~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def main():
    # test 1: signing and verifying a file
    print("Test 1: Signing and Verifying demo.txt")

    # generate signature keys
    public_key, private_key = generate_signature_keypair()

    # read the content of demo.txt
    with open("encryption/demo.txt", "r") as file:
        data = file.read()

    # sign the data
    signature = sign_data(data, private_key)
    print("Data signed successfully.")

    # verify the signature
    is_valid = verify_signature(data, signature, public_key)
    if is_valid:
        print("Signature is valid.")
        print("\nTest 1: Pass\n")
    else:
        print("Signature is invalid.")
        print("\nTest 1: Fail\n")


    # test 2: verifying a file with incorrect data
    print("Test 2: Verifying demo.txt with tampered data")

    # simulate data tampering
    modified_data = data + " tampered"

    # try verifying with the original public key
    is_valid = verify_signature(modified_data, signature, public_key)
    if not is_valid:
        print("Signature verification correctly failed for tampered data.")
        print("\nTest 2: Pass\n")
    else:
        print("Error: Signature verification should have failed.")
        print("\nTest 2: Fail\n")


    # test 3: verifying with a wrong public key
    print("Test 3: Verifying with an incorrect public key")

    # generate a new public/private keypair. simulates using the wrong public key
    wrong_public_key, wrong_private_key = generate_signature_keypair()

    # try verifying with the wrong public key
    is_valid = verify_signature(data, signature, wrong_public_key)
    if not is_valid:
        print("Signature verification correctly failed with wrong public key.")
        print("\nTest 3: Pass\n")
    else:
        print("Error: Signature verification should have failed with the wrong public key.")
        print("\nTest 3: Fail\n")

# main()
