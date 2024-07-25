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
import hashlib

from util import *

ser = serial.Serial("/dev/ttyACM0", 115200)

RESP_OK = b"\x00"
FRAME_SIZE = 280


def send_metadata(ser, metadata, debug=False):
    assert(len(metadata) == 2)
    version = u16(metadata[:2], endian='little')
    size = u16(metadata[2:], endian='little')

    print(f"Version: {version}\nSize: {size} bytes\nMessage Type: {msg_type}\nRelease Message: {rel_msg}\nIV: {iv}")

    # Handshake for update
    ser.write(b"U")

    print("Waiting for bootloader to enter update mode...")
    while ser.read(1).decode() != "U":
        print("got a byte")
        pass

    # Send size and version to bootloader.
    if debug:
        print(metadata)

    ser.write(metadata)

    # Wait for an OK from the bootloader.
    resp = ser.read(1)
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))


def send_frame(ser, frame, debug=False):
    ser.write(frame)  # Write the frame...

    if debug:
        print_hex(frame)

    resp = ser.read(1)  # Wait for an OK from the bootloader

    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))

    if debug:
        print("Resp: {}".format(ord(resp)))


def update(ser, infile, debug):
    # Open serial port. Set baudrate to 115200. Set timeout to 2 seconds.
    with open(infile, "rb") as fp:
        firmware_blob = fp.read()

    metadata = firmware_blob[:4]
    firmware = firmware_blob[4:]

    send_metadata(ser, metadata, debug=debug)

    msg_type = 1
    rsa_sign = hashlib.new('sha256')
    rsa_sign.update(data.encode()) 

    for idx, frame_start in enumerate(range(0, len(firmware), FRAME_SIZE)):
        data = firmware[frame_start : frame_start + FRAME_SIZE]

        # Construct frame.
        frame = idx + msg_type + p16(len(data), endian='big') + data + rsa_sign.hexdigest()

        msg_type = msg_type + 1

        send_frame(ser, frame, debug=debug)
        print(f"Wrote frame {idx} ({len(frame)} bytes)")

    print("Done writing firmware.")

    # Send a zero length payload to tell the bootlader to finish writing it's page.
    ser.write(p16(0x0000, endian='big'))
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
