#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
from pwn import *
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

def aes_encrypt(firmware):
    aes_key_directory = ''
    with open(aes_key_directory, 'rb') as f:
        aes_key = f.read()
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(firmware, 16))
    return ciphertext

def rsa_sign(encrypted_firmwware_and_metadata):
    rsa_priv_key_directory = ''
    with open(rsa_priv_key_directory, 'rb') as f:
        key = f.read()
    rsa_priv_key = RSA.import_key(key)
    h = SHA256.new(encrypted_firmwware_and_metadata)
    signature = pkcs1_15.new(rsa_priv_key).sign(h)
    return signature


def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, "rb") as fp:
        firmware = fp.read()
    firmware = aes_encrypt(firmware)
    # Append null-terminated message to end of firmware
    firmware_and_message = firmware + message.encode() + b"\00"
    # Pack version and size into two little-endian shorts
    metadata = p16(version, endian='little') + p16(len(firmware), endian='little') 
    signature = rsa_sign(metadata) 
    # Append firmware and message to metadata
    firmware_blob = metadata + firmware_and_message
    signature = rsa_sign(firmware_blob)
    firmware_blob  = firmware_blob + signature
    # Write firmware blob to outfile
    with open(outfile, "wb+") as outfile:
        outfile.write(firmware_blob)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)