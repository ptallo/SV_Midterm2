import os
import sys
from scapy.all import *


def main():
    message = "Hello World!"
    # Create 12 packets
    packets = [IP(dst="github.com") / TCP() for x in range(12)]
    responses = []

    # Encode message into packet ID
    encode_message_in_packets(packets, message)

    sys.stdout = open("output/packets.txt", 'w')

    # Send packets, collect responses, display packets
    for p in packets:
        responses.append(sr1(p))
        p.show()

    sys.stdout = open("output/responses.txt", 'w')
    # Display responses
    for i, r in enumerate(responses):
        print("Response {}".format(i))
        r.show()

    # Output the message
    sys.stdout = open("output/message.txt", 'w')
    print(decode_message_from_packets(responses))


def encode_message_in_packets(packets, message):
    for i, c in enumerate(message):
        packets[i][IP].id = encode_character_in_string(packets[i][IP].id, c)


def encode_character_in_string(string_to_modify, character):
    return string_to_modify


def decode_message_from_packets(packets):
    message = []
    for p in packets:
        message.append(decode_character_from_packet(p))
    return "".join(message)


def decode_character_from_packet(p):
    return "A"


if __name__ == "__main__":
    main()
