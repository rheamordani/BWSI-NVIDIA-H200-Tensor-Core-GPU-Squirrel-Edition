import os
import pathlib
import subprocess
import secrets
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")
FACTORY_OUTPUT = os.path.join(REPO_ROOT, "secret_build_output.txt")
BOOTLOADER_OUTPUT = os.path.join(REPO_ROOT, "bootloader.bin")


def generate_keys():
    # Generate a 256-bit key for AES encryption and decryption
    aes_key = secrets.token_bytes(32)

    # Generate a SHA-256 hash
    sha256_hash = hashlib.sha256(aes_key).digest()

    # Generate RSA keys for signing and verifying
    rsa_key = RSA.generate(2048)
    rsa_private_key = rsa_key.export_key()
    rsa_public_key = rsa_key.publickey().export_key()

    with open(FACTORY_OUTPUT, 'wb') as f:
        f.write(b"AES Key:\n")
        f.write(aes_key)
        f.write(b"\n\nSHA-256 Hash:\n")
        f.write(sha256_hash)
        f.write(b"\n\nRSA Private Key:\n")
        f.write(rsa_private_key)
        f.write(b"\n\nRSA Public Key:\n")
        f.write(rsa_public_key)

    with open(BOOTLOADER_OUTPUT, 'wb') as f:
        f.write(b"Bootloader binary placeholder\n")

    print("Keys generated and stored in secret_build_output.txt")


def make_bootloader() -> bool:
    # Build the bootloader from source.
    os.chdir(BOOTLOADER_DIR)

    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")

    # Return True if make returned 0, otherwise return False.
    return status == 0


if __name__ == "__main__":
    if make_bootloader():
        generate_keys()
        print("Bootloader built and keys generated successfully.")
    else:
        print("Bootloader build failed.")