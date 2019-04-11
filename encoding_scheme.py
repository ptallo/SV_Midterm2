from scapy.all import *

# Escape character to indicate the end of a message
escape_sequence = chr(65535)

# For demonstration purposes, we use the same one-time pad for all executions
# A real attacker would only run this program once, and write a new program for subsequent attacks
ONE_TIME_PAD = "oz81VXDcmSHM78yC8pOEzw8dlLJxOWh1d2vXfVsvEsY4SAhW4toUER8meGceU8C1cp568tDPkJHH5YHraun1gJbqHVSas5vNC9dfZZxtyAiavb9SxJrDgjdbRzxRhhsxwCSCyKL1lSog5BKBJGFB06tHXZ6RWTxGIWVt02RfNG8fstAUZXurJvS9EM4RrlREcP84E7LG"
random.seed(6969)
max_sequence_value = 2 ** 32


class SteganographyScheme:
    def encode_message_in_packets(self, packets, message):
        message = self.encrypt_or_decrpyt(message)
        for i, c in enumerate(message):
            self.encode_character_in_string(packets[i], c)
        self.encode_character_in_string(packets[len(packets) - 1], escape_sequence)

    def encode_character_in_string(self, input_packet, character):
        raise NotImplementedError("Abstract Class, this is not implemented")

    def decode_message_from_packets(self, packets):
        message = []
        for p in packets:
            character = self.decode_character_from_packet(p)
            if character != escape_sequence:
                message.append(character)
        encrypted_string = "".join(message)
        return self.encrypt_or_decrpyt(encrypted_string)

    def decode_character_from_packet(self, input_packet):
        raise NotImplementedError("Abstract Class, this is not implemented")

    def encrypt_or_decrpyt(self, message):
        if len(message) > len(ONE_TIME_PAD):
            raise Exception("Message is too long")
        return self.xor_two_str(message, ONE_TIME_PAD[0:len(message)])

    # Source for below function: https://stackoverflow.com/questions/36242887/how-to-xor-two-strings-in-python/36242949
    # With small modifications
    def xor_two_str(self, a, b):
        xored = []
        for i in range(max(len(a), len(b))):
            xored_value = ord(a[i % len(a)]) ^ ord(b[i % len(b)])
            xored.append(chr(xored_value))
        return ''.join(xored)


class IpIdSteganography(SteganographyScheme):
    def encode_character_in_string(self, input_packet, character):
        input_packet[IP].id = ord(character)
        input_packet[TCP].seq = random.randint(0, max_sequence_value)
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
