from scapy.all import *
import random

import utility

# For demonstration purposes, we use the same random seed (stored in a file) for all executions
# A real attacker would only run this program once, and write a new program with a new random seed 
# for subsequent attacks
random.seed(utility.get_random_seed())


class SteganographyScheme:
    def encode_message_in_packets(self, packets, message):
        message = self.encrypt_or_decrypt(message)
        for i, c in enumerate(message):
            self.encode_character_in_packet(packets[i], c)
        self.encode_character_in_packet(packets[len(packets) - 1], utility.get_escape_sequence())

    def encode_character_in_packet(self, input_packet, character):
        raise NotImplementedError("Abstract Class, this is not implemented")

    def decode_message_from_packets(self, packets, random_ints):
        message = [" " for x in random_ints]
        message_len = len(packets)
        for p in packets:
            character, position = self.decode_character_from_packet(p, random_ints)
            if character != utility.get_escape_sequence():
                message[position] = character
            else:
                message_len = position
        encrypted_string = "".join(message[:message_len])
        return utility.encrypt_or_decrypt(encrypted_string)

    def decode_character_from_packet(self, input_packet, random_ints):
        raise NotImplementedError("Abstract Class, this is not implemented")


class IpIdSteganography(SteganographyScheme):
    def encode_character_in_packet(self, input_packet, character):
        input_packet[IP].id = ord(character)
        input_packet[TCP].seq = random.randint(2 ** 31, 2 ** 32)

    def decode_character_from_packet(self, input_packet, random_ints):
        return chr(input_packet[IP].id), random_ints.index(input_packet[TCP].seq)
