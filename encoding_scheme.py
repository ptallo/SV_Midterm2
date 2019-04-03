from scapy.all import *

def encode_message_in_packets(packets, message):
    for i, c in enumerate(message):
        new_id = encode_character_in_string(packets[i][IP].id, c)
        packets[i][IP].id = new_id


def encode_character_in_string(string_to_modify, character):
    if type(string_to_modify) != str:
        string_to_modify = str(string_to_modify)
    bits_to_encode = string_to_bits(string_to_modify)
    code_bits = string_to_bits(character)
    bits_to_encode[len(bits_to_encode) - len(code_bits):] = code_bits
    return bits_to_string(bits_to_encode)


def decode_message_from_packets(packets):
    message = []
    for p in packets:
        message.append(decode_character_from_packet(p))
    return "".join(message)


def decode_character_from_packet(p):
    id_bits = string_to_bits(p[IP].id)
    bits_to_decode = id_bits[len(id_bits) - 8:]
    return bits_to_string(bits_to_decode)


def test_encode_decode_from_packets():
    message = "Hello World!"
    packets = [IP(dst="github.com") / TCP() for x in range(12)]

    encode_message_in_packets(packets, message)
    decoded_message = decode_message_from_packets(packets)
    if message != decoded_message:
        raise AssertionError("Message not equal to Decoded Message!")
