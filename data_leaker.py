import os
import sys
from scapy.all import *
import time

# Imports from our project
from encoding_scheme import *


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def filter_packet(p):
    return p.haslayer(IP) and p.haslayer(TCP)


def main():
    # Generate the output folder if it does not exist
    output_path = "./output/"
    os.makedirs(output_path, exist_ok=True)

    # Initialize message, and encrypt it
    message_to_send = "Hello World!"
    ip_steg = IpIdSteganography()
    encrypted_message = ip_steg.encrypt_or_decrpyt(message_to_send)
    encrypted_message = encrypted_message + (chr(65535))

    # Delete Output file if it exists already
    sys.stdout = open("output/packets.txt", "w")

    while len(encrypted_message) > 0:
        # Sniff one packet
        packets = sniff(store=True, lfilter=filter_packet, count=1)

        # Get one character to send from string
        char_to_send = encrypted_message[0]
        encrypted_message = encrypted_message[1:]

        # Encrypt character into packet then send it
        ip_steg.encode_character_in_packet(packets[0], char_to_send)
        send(packets[0])
        eprint("Packet Sent, len left {}".format(len(encrypted_message)))

        # Print packet sent to file
        packets[0].show()
        print("\n\n")

        # time.sleep(1)


if __name__ == "__main__":
    main()
