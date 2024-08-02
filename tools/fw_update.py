#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Updater Tool

A frame consists of two sections:
1. Two bytes for the length of the data section
2. A data section of length defined in the length section

[ 0x02 ]  [ variable ]
--------------------
| Length | Data... |
--------------------

In our case, the data is from one line of the Intel Hex formated .hex file

We write a frame to the bootloader, then wait for it to respond with an
OK message so we can write the next frame. The OK message in this case is
just a zero
"""

import argparse
from pwn import *
import time
import serial

from util import *
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

ser = serial.Serial("/dev/ttyACM0", 115200)

RESP_OK = b"\x04"


def send_first_frame(ser, begin_frame, debug=False):
    metadata = begin_frame [:4]
    assert(len(metadata) == 4)
    version = u16(metadata[:2], endian='little')
    size = u16(metadata[2:], endian='little')

    print(f"Version: {version}\nSize: {size} bytes\n")

    # Handshake for update
    ser.write(b"U")

    print("Waiting for bootloader to enter update mode...") 
    while ser.read(1).decode() != "U":
        print("got a byte")
        pass

    #    Send size and version to bootloader.
    if debug:
        print(metadata)

    print('begin frame: ')
    print_hex(begin_frame)
    print(f'length of frame 0: {len(begin_frame)}')

    ser.write(begin_frame)
    # Wait for an OK from the bootloader.
    print('waiting for bootloader confirmation')
    resp = ser.read(1)
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))    



def send_frame(ser, frame, debug=False):
    ser.write(frame)  # Write the frame...

    print('data frame: ')
    print_hex(frame)
    print(f'length of frame: {len(frame)}')

    if debug:
        print_hex(frame)

    resp = ser.read(1)  # Wait for an OK from the bootloader

    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))

    if debug:
        print("Resp: {}".format(ord(resp)))


def update(ser, infile, debug):
    # Open firmware file
    with open(infile, "rb") as fp:
        full_file = fp.read()

    begin_frame = full_file [:52]

    send_first_frame (ser, begin_frame)
    
    data_frames = full_file [52:]
    print(data_frames)

    # release_message_and_null_terminator = full_file [size + 32*num_frames + 2*num_frames: ]

    frames = [data_frames[i : i + 288] for i in range(0, len(data_frames), 288)]

    for frame in frames:
        send_frame(ser, frame)
        resp = ser.read(1)  # Wait for an OK from the bootloader
        time.sleep(0.1)
        if resp != RESP_OK:
            raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))


    print("Done writing firmware.")

    # Send a zero length payload to signal the bootloader to finish writing the page
    ser.write(p16(0x0000, endian='big'))
    # ser.write(release_message_and_null_terminator)

    resp = ser.read(1)  # Wait for an OK from the bootloader
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded to zero length frame with {}".format(repr(resp)))
    print(f"Wrote zero length frame (2 bytes)")


    return ser


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")

    parser.add_argument("--port", help="Does nothing, included to adhere to command examples in rule doc", required=False)
    parser.add_argument("--firmware", help="Path to firmware image to load.", required=False)
    parser.add_argument("--debug", help="Enable debugging messages.", action="store_true")
    args = parser.parse_args()

    update(ser=ser, infile=args.firmware, debug=args.debug)
    ser.close()