from scapy.all import *


def main():
    conf.verb = 0
    p = IP(dst="github.com") / TCP()
    r = sr1(p)
    r.show()


def encode_character_in_packet(packets, message):
    for i, c in enumerate(message):
        packets[i][IP].id = encode_character_in_string(packets[i][IP].id, c)


def encode_character_in_string(string_to_compare, character):
    return ""


if __name__ == "__main__":
    main()
