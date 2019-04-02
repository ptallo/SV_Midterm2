# Script for sending a IPv4 packet with a custom header
# Retrieved from http://www.bitforestinfo.com/2017/12/code-to-create-ipv4-packet-header-in-python.html

import socket
import struct

class IPPacket:
    def __init__(self, dst='127.0.0.1', src='192.168.1.101'):
        self.dst = dst
        self.src = src
        self.raw = None
        self.create_ipv4_fields_list()

    def assemble_ipv4_fields(self):
        self.raw = struct.pack(
            '!BBHHHBBH4s4s',
            self.ip_ver,    # IP Version
            self.ip_dfc,    # Differentiated Service Field
            self.ip_tol,    # Total Length
            self.ip_idf,    # Identification
            self.ip_flg,    # Flags
            self.ip_ttl,    # Time to live
            self.ip_proto,  # Protocol
            self.ip_chk,    # Checksum
            self.ip_saddr,  # Source IP
            self.ip_daddr   # Destination IP
        )
        return self.raw

    def create_ipv4_fields_list(self):

        # ---- [Internet Protocol Version] ----
        ip_ver = 4
        ip_vhl = 5

        self.ip_ver = (ip_ver << 4) + ip_vhl
        print("IP Version : " + str(self.ip_ver))

        # ---- [ Differentiated Service Field ]
        ip_dsc = 0
        ip_ecn = 0

        self.ip_dfc = (ip_dsc << 2) + ip_ecn
        print("Differentiated Service Field : " + str(self.ip_dfc))

        # ---- [ Total Length]
        self.ip_tol = 0
        print("Total Length : " + str(self.ip_tol))

        # ---- [ Identification ]
        self.ip_idf = 54321
        print("Identification : " + str(self.ip_idf))

        # ---- [ Flags ]
        ip_rsv = 0
        ip_dtf = 0
        ip_mrf = 0
        ip_frag_offset = 0

        self.ip_flg = (ip_rsv << 7) + (ip_dtf << 6) + \
            (ip_mrf << 5) + (ip_frag_offset)
        
        print("IP Flags : " + str(self.ip_flg))

        # ---- [ Time to Live ]
        self.ip_ttl = 255
        print("Time to Live : " + str(self.ip_ttl))

        # ---- [ Protocol ]
        self.ip_proto = socket.IPPROTO_TCP
        print("Protocol : " + str(self.ip_proto))

        # ---- [ Checksum ]
        self.ip_chk = 0
        print("Checksum : " + str(self.ip_chk))

        # ---- [ Source Address ]
        self.ip_saddr = socket.inet_aton(self.src)
        print("Source Address : " + str(self.ip_saddr))

        # ---- [ Destination Address ]
        self.ip_daddr = socket.inet_aton(self.dst)
        print("Destination Address : " + str(self.dst))


        return


if __name__ == '__main__':
    # Create Raw Socket
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    ip = IPPacket()
    ip.assemble_ipv4_fields()

    s.sendto(ip.raw, ('127.0.0.1', 0))
