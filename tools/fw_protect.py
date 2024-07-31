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
<<<<<<< HEAD


def aes_encrypt(firmware):
    with open('secret_build_output', 'rb') as f:
        aes_key = f.read(32)
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(firmware, 16))
    return ciphertext, iv
=======
>>>>>>> d91b0eeff54bbceec4418da82bb55b2381f658cb


def aes_encrypt(firmware):
    with open('secret_build_output', 'rb') as f:
        aes_key = f.read(32)
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(firmware, 16))
    return ciphertext, iv

def rsa_sign(firmware):
    with open('secret_build_output', 'rb') as f:
        f.seek(32)
        key = f.read()
    rsa_priv_key = RSA.import_key(key)
    h = SHA256.new(firmware)
    signature = pkcs1_15.new(rsa_priv_key).sign(h)
    return signature

def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, "rb") as fp:
<<<<<<< HEAD
        firmware = fp.read() #reading firmware
    aes_output = aes_encrypt(firmware) 
    firmware = aes_output[0]
    iv = aes_output[1]
    # Append null-terminated message to end of firmware
    firmware_and_message = firmware + message.encode() + b"\00"
    # Pack version and size into two little-endian shorts
    metadata = p16(version, endian='little') + p16(len(firmware), endian='little')
    # Append firmware and message to metadata
    firmware_blob = metadata + iv + firmware_and_message
=======
        firmware = fp.read()
    # encrypt firmware
    aes_output = aes_encrypt(firmware)
    firmware = aes_output[0]
    iv = aes_output[1]
    # pack metadata
    metadata = p16(version, endian='little') + p16(len(firmware), endian='little')
    # write metadata, iv, and rsa signt
    firmware_blob = metadata + iv + rsa_sign(metadata)
    print(len(rsa_sign(metadata)))
    frames = [firmware[i:i + 100] for i in range(0, len(firmware), 100)]
    for frame in frames:
        rsa_signature = rsa_sign(frame)
        frame_to_send = p16(len(frame), endian = 'little') + frame + rsa_signature
        firmware_blob += frame_to_send
>>>>>>> d91b0eeff54bbceec4418da82bb55b2381f658cb
    # Write firmware blob to outfile
    with open(outfile, "wb+") as outfile:
        aes_output = aes_encrypt(message.encode())
        release_message_ciphertext = aes_output[0]
        print(release_message_ciphertext)
        firmware_blob += release_message_ciphertext
        outfile.write(firmware_blob)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

<<<<<<< HEAD
    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)

=======
    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)
>>>>>>> d91b0eeff54bbceec4418da82bb55b2381f658cb
