import os
import sys
from scapy.all import *
import time
import utility

# Imports from our project
from encoding_scheme import *

def filter_packet(p):
    return p.haslayer(IP) and p.haslayer(TCP)


def main():
    # Generate the output folder if it does not exist
    output_path = "./output/"
    os.makedirs(output_path, exist_ok=True)

    # Create 1 packet for each character in the message
    f = open("input/message.txt", "r")
    lines = f.readlines()
    f.close()

    message = "".join(lines)
    ip_steg = IpIdSteganography()
    encrypted_message = utility.encrypt_or_decrypt(message)

    sys.stdout = open("output/sent_packets.txt", "w")
    # Send packets, collect responses, display packets
    while len(encrypted_message) > 0:
        # get the encrypted character
        character_to_encrypt = encrypted_message[0]
        encrypted_message = encrypted_message[1:]

        # Create a packet and encode the character in the packet
        p = IP(dst="yahoo.com") / TCP()
        ip_steg.encode_character_in_packet(p, character_to_encrypt)
        send(p)
        p.show()

    # Send the end sequence to indicate that the message is finished being sent
    p = IP(dst="yahoo.com") / TCP()
    ip_steg.encode_character_in_packet(p, chr(utility.get_escape_sequence()))
    send(p)
    p.show()





if __name__ == "__main__":
    main()
