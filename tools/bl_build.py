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
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")

def generate_keys():
    aes_key = get_random_bytes(16)
    rsa_key = RSA.generate(2048)
    rsa_private_key = rsa_key.export_key()
    rsa_public_key = rsa_key.publickey().export_key()
    with open('secret_build_output', 'wb') as f:
        f.write(aes_key)
        f.write(rsa_private_key)
    with open('/home/hacker/NVIDIA-H200-Tensor-Core-GPU-Squirrel-Edition/bootloader/inc/keys.h', 'w') as f:
        bytes_array = ""
        for i in range(len(aes_key)):
            if i == len(aes_key) - 1:
                bytes_array += str(hex(aes_key[i]))
            else:
                bytes_array += str(hex(aes_key[i])) + ", "
        print(len(aes_key))
        print(len(rsa_public_key))
        aes_header_file =  'const uint8_t aes_key' + '[' + str(len(bytes_array))+ ']' + '= ' +  "{" + bytes_array + "};\n"
        bytes_array = ""
        for i in range(len(rsa_public_key)):
            if i == len(rsa_public_key) - 1:
                bytes_array += str(hex(rsa_public_key[i]))
            else:
                bytes_array += str(hex(rsa_public_key[i])) + ", "
        print(bytes_array)
        rsa_header_file =  'const uint8_t rsa_pub_key' + '[' + str(len(bytes_array)) + ']' + '= ' +  "{" + bytes_array + "};\n"
        f.write('#ifndef KEYH #define KEYH\n')        
        f.write(aes_header_file)
        f.write(rsa_header_file)
        f.write('#endif')


def make_bootloader() -> bool:
    # Build the bootloader from source.

    os.chdir(BOOTLOADER_DIR)

    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")

    # Return True if make returned 0, otherwise return False.
    return status == 0


if __name__ == "__main__":
    generate_keys()
    make_bootloader()