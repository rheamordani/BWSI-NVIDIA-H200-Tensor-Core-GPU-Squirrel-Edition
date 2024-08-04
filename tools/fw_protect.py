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
from util import *

iv = get_random_bytes(16)
def aes_encrypt(firmware):
    with open('secret_build_output', 'rb') as f:
        aes_key = f.read(32)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(firmware)
    return ciphertext

def sha256_hash(firmware):
    h = SHA256.new()
    h.update(firmware)
    return h.digest()

def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, "rb") as fp:
        firmware = fp.read()
    
    release_message = message.encode()

    # print(release_message)

    release_message_size = p16(len(release_message), endian = 'little')

    # print(release_message_size)

    # pack metadata
    metadata = p16(version, endian='little') + p16(len(firmware), endian='little')
    
    # hash metadata
    metadata_hash = sha256_hash(metadata)
    
    begin_frame = release_message_size + release_message + metadata + iv + metadata_hash
    
    firmware_blob = begin_frame

    # append frames of encrypted firmware with the hash of the decrypted_data   
    frames = [firmware[i : i + 16] for i in range(0, len(firmware), 16)]
    # print(frames)
    for frame in frames:
        if len(frame)!= 16:
            while True:
                frame = frame + b'\x00'
                if len(frame) == 16:
                    break
        firmware_hash = sha256_hash(frame)
        # print_hex(frame)
        encrypted_firmware = aes_encrypt(frame)
        # print_hex(encrypted_firmware)
        # print()
        # print()
        # firmware_hash = sha256_hash(encrypted_firmware)
        # print_hex(firmware_hash)
        # print(f'length of enc firmware:  {len(encrypted_firmware)}')
        frame_to_send = encrypted_firmware + firmware_hash
        # print(f'len of frame to send: {len(frame_to_send)}')
        firmware_blob += frame_to_send

    # Write firmware blob to outfile
    with open(outfile, "wb+") as outfile:
        # release_message_ciphertext = aes_encrypt(message.encode())
        # print(release_message_ciphertext)
        # firmware_blob += release_message_ciphertext
        outfile.write(firmware_blob)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)