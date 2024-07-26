#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Bootloader Build Tool

This tool is responsible for building the bootloader from source and copying
the build outputs into the host tools directory for programming.
"""

import os
import pathlib
import subprocess
import secrets
import hashlib
from Crypto.PublicKey import RSA

REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")
OUTPUT_FILE = os.path.join(REPO_ROOT, "secret_build_output.txt")

def make_bootloader() -> bool:
    """Build the bootloader from source."""
    os.chdir(BOOTLOADER_DIR)

    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")

    # Return True if make returned 0, otherwise return False.
    return status == 0

def generate_aes_key() -> bytes:
    """Generate a 256-bit AES key."""
    return secrets.token_bytes(32)  # 32 bytes = 256 bits

def generate_sha256_hash(data: bytes) -> str:
    """Generate a SHA-256 hash of the provided data."""
    sha256_hash = hashlib.sha256(data).hexdigest()
    return sha256_hash

def generate_rsa_keys() -> (bytes, bytes):
    """Generate a 256-byte RSA key pair."""
    key = RSA.generate(2048)  # Generate a 2048-bit RSA key
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    return private_key, public_key

def write_to_file(aes_key: bytes, sha256_hash: str, private_key: bytes, public_key: bytes):
    """Write the generated keys and hashes to a file."""
    with open(OUTPUT_FILE, 'w') as f:
        f.write(f"AES Key (base64): {aes_key.hex()}\n")  # Store AES key in hex format
        f.write(f"SHA-256 Hash: {sha256_hash}\n")
        f.write(f"RSA Private Key: {private_key.decode()}\n")
        f.write(f"RSA Public Key: {public_key.decode()}\n")

def main():
    if make_bootloader():
        print("Bootloader compiled successfully.")
        
        # Generate keys
        aes_key = generate_aes_key()
        data_to_hash = b"Sample data for hashing."  # Replace with actual data if needed
        sha256_hash = generate_sha256_hash(data_to_hash)
        private_key, public_key = generate_rsa_keys()

        # Write outputs to file
        write_to_file(aes_key, sha256_hash, private_key, public_key)
        print(f"Keys and hashes written to {OUTPUT_FILE}.")
    else:
        print("Bootloader compilation failed.")

if __name__ == "__main__":
    main()