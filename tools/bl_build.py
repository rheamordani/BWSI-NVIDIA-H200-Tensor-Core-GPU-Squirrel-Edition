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
    aes_key = get_random_bytes(32)
    with open('secret_build_output', 'wb') as f:
        f.write(aes_key)
    with open('bootloader/inc/keys.h', 'w') as f:
        bytes_array = ""
        for i in range(len(aes_key)):
            if i == len(aes_key) - 1:
                bytes_array += str(hex(aes_key[i]))
            else:
                bytes_array += str(hex(aes_key[i])) + ", "
        aes_header_file =  'const uint8_t aes_key' + '[32]' + '= ' +  "{" + bytes_array + "};\n"
        f.write('#ifndef KEYH \n#define KEYH\n')        
        f.write(aes_header_file)
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

