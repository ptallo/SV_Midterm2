from scapy.all import *
from utility import *


class SteganographyScheme:
    def encode_message_in_packets(self, packets, message):
        for i, c in enumerate(message):
            self.encode_character_in_string(packets[i], c)

    def encode_character_in_string(self, input_packet, character):
        raise NotImplementedError("Abstract Class, this is not implemented")

    def decode_message_from_packets(self, packets):
        message = []
        for p in packets:
            message.append(decode_character_from_packet(p))
        return "".join(message)

    def decode_character_from_packet(self, input_packet):
        raise NotImplementedError("Abstract Class, this is not implemented")


class IpIdSteganography(SteganographyScheme):
    def encode_character_in_string(self, input_packet, character):
        string_to_modify = input_packet[IP].id
        if type(string_to_modify) != str:
            string_to_modify = str(string_to_modify)
        bits_to_encode = string_to_bits(string_to_modify)
        code_bits = string_to_bits(character)
        bits_to_encode[len(bits_to_encode) - len(code_bits):] = code_bits
        input_packet[IP].id = bits_to_string(bits_to_encode)

    def decode_character_from_packet(self, input_packet):
        id_bits = string_to_bits(input_packet[IP].id)
        bits_to_decode = id_bits[len(id_bits) - 8:]
        return bits_to_string(bits_to_decode)


def test_encode_decode_from_packets():
    message = "Hello World!"
    packets = [IP(dst="github.com") / TCP() for x in range(12)]

    IpIdSteganography.encode_message_in_packets(packets, message)
    decoded_message = IpIdSteganography.decode_message_from_packets(packets)
    if message != decoded_message:
        raise AssertionError("Message not equal to Decoded Message!")
