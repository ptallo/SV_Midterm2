from scapy.all import *

def main():
    conf.verb = 0
    p = IP(dst="github.com")/TCP()
    r = sr1(p)
    r.show()

if __name__ == "__main__":
    main()