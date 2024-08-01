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

iv = get_random_bytes(16)
print(iv.hex())
def aes_encrypt(firmware):
    with open('secret_build_output', 'rb') as f:
        aes_key = f.read(32)
        print(aes_key.hex())
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(firmware, 16))
    return ciphertext

def hash(firmware):
    h = SHA256.new()
    h.update(firmware)
    return h.digest()

def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, "rb") as fp:
        firmware = fp.read()
    # encrypt firmware
    firmware = aes_encrypt(firmware)
    # pack metadata
    metadata = p16(version, endian='little') + p16(len(firmware), endian='little')
    firmware_blob = metadata + iv + hash(metadata)
    print(len(hash(metadata)))
    frames = [firmware[i:i + 100] for i in range(0, len(firmware), 100)]
    for frame in frames:
        frame_hash = hash(frame)
        frame_to_send = p16(len(frame), endian = 'little') + frame + frame_hash
        firmware_blob += frame_to_send
    # Write firmware blob to outfile
    with open(outfile, "wb+") as outfile:
        release_message_ciphertext = aes_encrypt(message.encode())
        release_message_size = len(message.encode())
        firmware_blob += p16(release_message_size, endian = 'little')
        firmware_blob += release_message_ciphertext
        outfile.write(firmware_blob)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)