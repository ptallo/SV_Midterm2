from scapy.all import *
import random

import utility

# For demonstration purposes, we use the same one-time pad for all executions
# A real attacker would only run this program once, and write a new program for subsequent attacks
random.seed(utility.get_random_seed())


class SteganographyScheme:
    def encode_message_in_packets(self, packets, message):
        message = self.encrypt_or_decrypt(message)
        for i, c in enumerate(message):
            self.encode_character_in_packet(packets[i], c)
        self.encode_character_in_packet(packets[len(packets) - 1], utility.get_escape_sequence())

    def encode_character_in_packet(self, input_packet, character):
        raise NotImplementedError("Abstract Class, this is not implemented")

    def decode_message_from_packets(self, packets):
        message = []
        for p in packets:
            character = self.decode_character_from_packet(p)
            if character != utility.get_escape_sequence():
                message.append(character)
        encrypted_string = "".join(message)
        return utility.encrypt_or_decrypt(encrypted_string)

    def decode_character_from_packet(self, input_packet):
        raise NotImplementedError("Abstract Class, this is not implemented")


class IpIdSteganography(SteganographyScheme):
    def encode_character_in_packet(self, input_packet, character):
        input_packet[IP].id = ord(character)
        input_packet[TCP].seq = random.randint(2 ** 31, 2 ** 32)

    def decode_character_from_packet(self, input_packet):
        return chr(input_packet[IP].id)
