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

    # Generate RSA keys for signing and verifying
    rsa_key = RSA.generate(2048)
    rsa_private_key = rsa_key.export_key()
    rsa_public_key = rsa_key.publickey().export_key()

    with open(FACTORY_OUTPUT, 'wb') as f:
        f.write(aes_key)
        f.write(rsa_private_key)
        f.write(rsa_public_key)
    with open('inc/keys.h', 'w') as f:
        aes_key = bytearray(aes_key)
        rsa_public_key = bytearray(rsa_public_key)
        f.write(f"#define AES_key {aes_key}")
        f.write(f"#define RSA Public Key {rsa_public_key}")

def make_bootloader() -> bool:
    # Build the bootloader from source.
    os.chdir(BOOTLOADER_DIR)

    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")

    # Return True if make returned 0, otherwise return False.
    return status == 0


if __name__ == "__main__":
    make_bootloader()
    generate_keys()
    print("Bootloader built and keys generated successfully.")