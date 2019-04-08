import encoding_scheme


def main():
    num_packets = 12
    # Create Berkeley Packet Filter (BPF) string for sniffing packets
    # Filter will throw out any packets that do not match the IP src and dst
    bpf_filter = "dst host github.com and src host localhost"

    # Sniff until num_packets packets match the BPF filter
    sniffed_packets = sniff(store=True, count=num_packets, filter=bpf_filter)
    sys.stdout = open("output/packets.txt", 'w')
    ip_steg = IpIdSteganography()
    print(ip_steg.decode_message_from_packets(sniffed_packets))

if __name__ == "__main__":
    main()