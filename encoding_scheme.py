from scapy.all import *
from utility import *
import numpy as np

escape_sequence = chr(65535)

class SteganographyScheme:
    def encode_message_in_packets(self, packets, message):
        for i, c in enumerate(message):
            self.encode_character_in_string(packets[i], c)
        self.encode_character_in_string(packets[len(packets)-1], escape_sequence)

    def encode_character_in_string(self, input_packet, character):
        raise NotImplementedError("Abstract Class, this is not implemented")

    def decode_message_from_packets(self, packets):
        message = []
        for p in packets:
            character = self.decode_character_from_packet(p)
            if character != escape_sequence:
                message.append(character)
        return "".join(message)

    def decode_character_from_packet(self, input_packet):
        raise NotImplementedError("Abstract Class, this is not implemented")


class IpIdSteganography(SteganographyScheme):
    def encode_character_in_string(self, input_packet, character):
        input_packet[IP].id = ord(character)
        if len(str(character)) > 2:
            raise Exception("Stringified number length is too long!")

    def decode_character_from_packet(self, input_packet):
        return chr(input_packet[IP].id)


def test_encode_decode_from_packets():
    message = "Hello World!"
    packets = [IP(dst="yahoo.com") / TCP() for x in range(12)]

    ip_steg = IpIdSteganography()
    ip_steg.encode_message_in_packets(packets, message)
    decoded_message = ip_steg.decode_message_from_packets(packets)
    if message != decoded_message:
        raise AssertionError("Message not equal to Decoded Message!")
    print(decoded_message)


if __name__ == "__main__":
    test_encode_decode_from_packets()
